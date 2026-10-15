/**
 * dsh-protect-generated-files: stops hand edits to generated files.
 *
 * Runs on `tools/pre-execute` for `write`, `edit`, and `str_replace_editor`,
 * plus `sed -i`/`perl -pi` style in-place edits from the shell. When the
 * target is a lockfile, a known build/codegen output, or carries a generated
 * marker in its header, the call is blocked and the model is told which
 * source to change and what to run. An identical retry confirms an
 * intentional edit (for example, a one-off hotfix to vendored code).
 *
 * @module dsh-protect-generated-files
 */
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import { generatedInfo, type GeneratedInfo } from './detect.ts'
import { canonicalJson, fileMutation, readExisting, resolvePath, workspaceOf } from './shared/files.ts'

export { generatedInfo, hintFor, DEFAULT_GENERATED_GLOBS } from './detect.ts'
export type { GeneratedInfo, GeneratedOptions } from './detect.ts'

export const name = 'protect-generated-files'

/** Plugin configuration. */
export interface Config {
  mode: 'deny' | 'ask'
  /** Extra globs treated as generated, mapped to the hint shown to the model. */
  extraGlobs: Record<string, string>
  /** Globs never treated as generated. */
  ignore: string[]
  /** Use the built-in output globs (dist/, node_modules/, *.pb.go, *.min.js, ...). Lockfiles are always on. */
  defaultGlobs: boolean
  /** Leading lines searched for `@generated` / `DO NOT EDIT` markers. */
  headerLines: number
  allowIdenticalRetry: boolean
  /** Also inspect in-place shell edits (`sed -i`, `perl -pi`, `> file`). */
  guardShell: boolean
  shellTools: string[]
  maxFileBytes: number
}

export const Config: Schema<Config> = Schema.object({
  mode: Schema.union(['deny', 'ask']).default('deny'),
  extraGlobs: Schema.dict(Schema.string()).default({}),
  ignore: Schema.array(Schema.string()).default([]),
  defaultGlobs: Schema.boolean().default(true),
  headerLines: Schema.natural().min(1).default(15),
  allowIdenticalRetry: Schema.boolean().default(true),
  guardShell: Schema.boolean().default(true),
  shellTools: Schema.array(Schema.string()).default(['bash', 'pwsh']),
  maxFileBytes: Schema.natural().default(5_000_000),
}) as Schema<Config>

/**
 * Render the model-facing reason.
 * @param path - workspace-relative path.
 * @param info - why it is generated.
 * @param retryAllowed - whether an identical retry is accepted.
 * @returns the denial text.
 */
export function denialText(path: string, info: GeneratedInfo, retryAllowed: boolean): string {
  const why = info.via === 'marker' ? `its header says it is generated (\`${info.evidence}\`)` : `it is a generated file (matches \`${info.evidence}\`)`
  return `dsh-protect-generated-files blocked this edit to ${path}: ${why}. A hand edit will be overwritten the next time it is regenerated, or leave it out of sync with its source. `
    + `Instead: ${info.hint}.`
    + (retryAllowed ? ' If a direct edit really is the right call here, repeat the identical call once to confirm.' : '')
}

/** Targets of in-place shell edits: `sed -i … file`, `perl -pi … file`, `> file`, `tee file`. */
export function shellEditTargets(command: string): string[] {
  const out: string[] = []
  for (const m of command.matchAll(/(?:^|[;&|]\s*)(?:sed\s+(?:-[a-zA-Z]*i\S*|--in-place\S*)|perl\s+-[a-zA-Z]*p[a-zA-Z]*i\S*|perl\s+-[a-zA-Z]*i[a-zA-Z]*p\S*)\s+([^;&|\n]+)/g)) {
    const words = m[1]!.match(/'[^']*'|"[^"]*"|\S+/g) ?? []
    // The last non-flag word(s) after the script are files; take words that look like paths.
    for (const w of words.slice(1)) if (!w.startsWith('-') && !/^['"]/.test(w)) out.push(w)
  }
  for (const m of command.matchAll(/(?:^|[^>&\d])>{1,2}\s*([^\s;&|<>]+)/g)) out.push(m[1]!)
  for (const m of command.matchAll(/\btee\s+(?:-a\s+)?([^\s;&|]+)/g)) out.push(m[1]!)
  // PowerShell: Set-Content / Add-Content / Out-File / Tee-Object, with -Path/-FilePath or a first positional path.
  for (const m of command.matchAll(/(?:^|[;&|]\s*|\|\s*)(?:set-content|add-content|out-file|tee-object|sc|ac)\b([^;&|\n]*)/gi)) {
    const words = m[1]!.match(/'[^']*'|"[^"]*"|\S+/g) ?? []
    const named = words.findIndex(w => /^-(?:path|filepath|literalpath)$/i.test(w))
    const target = named !== -1 ? words[named + 1] : words.find(w => !w.startsWith('-'))
    if (target !== undefined) out.push(target.replace(/^['"]|['"]$/g, ''))
  }
  return out.filter(p => p !== '/dev/null' && !/^\$null$/i.test(p) && !p.startsWith('&')).map(p => p.replaceAll('\\', '/'))
}

export function apply(ctx: Context, config: Config): void {
  const pending = new Set<string>()
  const remember = (key: string): void => {
    pending.add(key)
    if (pending.size > 200) pending.delete(pending.values().next().value!)
  }
  const MANIFESTS = ['package.json', 'Cargo.toml', 'go.mod', 'composer.json', 'Gemfile', 'pyproject.toml', 'setup.py', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'deno.json', 'mix.exs', 'pubspec.yaml']
  const optionsFor = (workspace: string) => ({
    extraGlobs: config.extraGlobs,
    ignore: config.ignore,
    defaultGlobs: config.defaultGlobs,
    headerLines: config.headerLines,
    isProjectRoot: (dir: string) => dir === '' || MANIFESTS.some(m => existsSync(join(workspace, dir, m))),
  })
  const shellTools = new Set(config.shellTools)

  const check = async (path: string, workspace: string): Promise<{ relative: string; info: GeneratedInfo } | undefined> => {
    const { absolute, relative } = resolvePath(path, workspace)
    if (relative.startsWith('../') && !relative.includes('node_modules/')) return undefined
    const content = await readExisting(absolute, config.maxFileBytes)
    const info = generatedInfo(relative, content, optionsFor(workspace))
    return info === undefined ? undefined : { relative, info }
  }

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>) => {
    const workspace = workspaceOf(exec)
    let hit: { relative: string; info: GeneratedInfo } | undefined
    if (shellTools.has(exec.name)) {
      if (!config.guardShell) return next()
      const command = (exec.arguments as { command?: unknown } | null)?.command
      if (typeof command !== 'string') return next()
      for (const target of shellEditTargets(command)) {
        hit = await check(target, workspace)
        if (hit !== undefined) break
      }
    } else {
      const mutation = fileMutation(exec)
      if (mutation === undefined) return next()
      hit = await check(mutation.path, workspace)
    }
    if (hit === undefined) return next()
    const key = createHash('sha256').update(`${exec.name}\0${workspace}\0${canonicalJson(exec.arguments)}`).digest('hex')
    if (config.allowIdenticalRetry && pending.delete(key)) return next()
    const text = denialText(hit.relative, hit.info, config.allowIdenticalRetry)
    if (config.mode === 'ask') {
      return { kind: 'ask', reason: text, displayReason: { en: `${hit.relative} is a generated file. ${hit.info.hint}.` } }
    }
    if (config.allowIdenticalRetry) remember(key)
    return { kind: 'deny', reason: text }
  })
}
