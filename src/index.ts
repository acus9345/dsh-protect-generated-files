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
import { resolveConfig } from './shared/live.ts'

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

// Every field is `.volatile()` so the settings page on DSH's Plugins page can
// change it live; `apply` reads the current values on each call.
export const Config: Schema<Config> = Schema.object({
  mode: Schema.union(['deny', 'ask']).default('deny').volatile(),
  extraGlobs: Schema.dict(Schema.string()).default({}).volatile(),
  ignore: Schema.array(Schema.string()).default([]).volatile(),
  defaultGlobs: Schema.boolean().default(true).volatile(),
  headerLines: Schema.natural().min(1).default(15).volatile(),
  allowIdenticalRetry: Schema.boolean().default(true).volatile(),
  guardShell: Schema.boolean().default(true).volatile(),
  shellTools: Schema.array(Schema.string()).default(['bash', 'pwsh']).volatile(),
  maxFileBytes: Schema.natural().default(5_000_000).volatile(),
}) as unknown as Schema<Config>

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

const stripQuotes = (token: string): string =>
  (token.length >= 2 && ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"))))
    ? token.slice(1, -1)
    : token

const CMD_WRAPPERS = new Set(['command', 'sudo', 'env', 'exec', 'time', 'nohup', 'then', 'do', 'else', 'elif', 'if'])
const WRAPPER_ARG_FLAGS: Record<string, { short: string; long: ReadonlySet<string> }> = {
  sudo: {
    short: 'ughprtCDRTU',
    long: new Set(['--user', '--group', '--host', '--prompt', '--role', '--type', '--close-from', '--chdir', '--chroot', '--command-timeout', '--other-user']),
  },
  env: {
    short: 'uCSP',
    long: new Set(['--unset', '--chdir', '--split-string']),
  },
  exec: {
    short: 'a',
    long: new Set(),
  },
}
const PWSH_WRITE_RE = /^(?:set-content|add-content|out-file|tee-object|sc|ac)$/i

function wrapperFlagTakesArg(wrapper: string, flag: string): boolean {
  const spec = WRAPPER_ARG_FLAGS[wrapper]
  if (spec === undefined) return false
  if (flag.startsWith('--')) return spec.long.has(flag)
  if (!/^-[a-zA-Z]+$/.test(flag)) return false
  for (let i = 1; i < flag.length - 1; i += 1) {
    if (spec.short.includes(flag[i]!)) return false
  }
  return spec.short.includes(flag[flag.length - 1]!)
}

function readBacktick(input: string, start: number, inDoubleQuotes: boolean): { end: number; body: string } | undefined {
  let i = start + 1
  let body = ''
  while (i < input.length) {
    const ch = input[i]!
    if (ch === '\\' && i + 1 < input.length) {
      const next = input[i + 1]!
      if (next === '\\' || next === '`' || next === '$' || (inDoubleQuotes && next === '"')) {
        body += next
        i += 2
        continue
      }
    }
    if (ch === '`') return { end: i + 1, body }
    body += ch
    i += 1
  }
  return undefined
}

interface SubstFrame {
  current: string[]
  parenDepth: number
  resume: 'word' | 'dquote'
  wordStart: number
  wordTarget: 'command' | 'redirect' | 'discard'
}

function scanShell(input: string): { commands: string[][]; redirects: string[]; nested: string[] } {
  const commands: string[][] = []
  const redirects: string[] = []
  const nested: string[] = []
  const stack: SubstFrame[] = []
  let current: string[] = []
  let parenDepth = 0
  let i = 0

  const flush = (): void => {
    if (current.length > 0) {
      commands.push(current)
      current = []
    }
  }

  const commitWord = (target: 'command' | 'redirect' | 'discard', word: string): void => {
    if (word === '') return
    if (target === 'command') current.push(word)
    else if (target === 'redirect') redirects.push(stripQuotes(word))
  }

  const readWord = (wordTarget: 'command' | 'redirect' | 'discard', resumeInDquote = false, wordStart = i): void => {
    let inDquote = resumeInDquote
    while (i < input.length) {
      if (inDquote) {
        const dc = input[i]!
        if (dc === '\\' && i + 1 < input.length) {
          i += 2
          continue
        }
        if (dc === '$' && input[i + 1] === '(') {
          stack.push({ current, parenDepth, resume: 'dquote', wordStart, wordTarget })
          current = []
          parenDepth = 0
          i += 2
          return
        }
        if (dc === '`') {
          const sub = readBacktick(input, i, true)
          if (sub !== undefined) {
            nested.push(sub.body)
            i = sub.end
            continue
          }
        }
        if (dc === '"') {
          i += 1
          inDquote = false
          continue
        }
        i += 1
        continue
      }
      const ch = input[i]!
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === ';' || ch === '&' || ch === '|' || ch === '(' || ch === ')' || ch === '{' || ch === '}' || ch === '<' || ch === '>') {
        break
      }
      if (ch === "'") {
        const close = input.indexOf("'", i + 1)
        i = close === -1 ? input.length : close + 1
        continue
      }
      if (ch === '"') {
        i += 1
        inDquote = true
        continue
      }
      if (ch === '$' && input[i + 1] === '(') {
        stack.push({ current, parenDepth, resume: 'word', wordStart, wordTarget })
        current = []
        parenDepth = 0
        i += 2
        return
      }
      if (ch === '`') {
        const sub = readBacktick(input, i, false)
        if (sub !== undefined) {
          nested.push(sub.body)
          i = sub.end
          continue
        }
      }
      if (ch === '\\' && i + 1 < input.length && input[i + 1] !== '\n') {
        i += 2
        continue
      }
      i += 1
    }
    commitWord(wordTarget, input.slice(wordStart, i))
  }

  while (i < input.length) {
    const ch = input[i]!
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i += 1
      continue
    }
    if (ch === '#') {
      const nl = input.indexOf('\n', i + 1)
      i = nl === -1 ? input.length : nl
      continue
    }
    if (ch === '&' && input[i + 1] === '>') {
      i += 2
      if (input[i] === '>') i += 1
      while (i < input.length && (input[i] === ' ' || input[i] === '\t')) i += 1
      readWord('redirect')
      continue
    }
    if (ch === '(') {
      flush()
      if (stack.length > 0) parenDepth += 1
      i += 1
      continue
    }
    if (ch === ')') {
      flush()
      if (stack.length > 0) {
        if (parenDepth > 0) {
          parenDepth -= 1
          i += 1
          continue
        }
        const frame = stack.pop()!
        current = frame.current
        parenDepth = frame.parenDepth
        i += 1
        readWord(frame.wordTarget, frame.resume === 'dquote', frame.wordStart)
        continue
      }
      i += 1
      continue
    }
    if (ch === ';' || ch === '\n' || ch === '&' || ch === '|' || ch === '{' || ch === '}') {
      flush()
      i += 1
      continue
    }
    // Optional fd prefix immediately before a redirection operator (e.g. `2>&1`, `1> file`, `1<> file`).
    if (ch >= '0' && ch <= '9') {
      let j = i + 1
      while (j < input.length && input[j]! >= '0' && input[j]! <= '9') j += 1
      if (input[j] === '<' || input[j] === '>') i = j
    }
    const op = input[i]
    if (op === '>') {
      i += 1
      if (input[i] === '>' || input[i] === '|') i += 1
      const isFdDup = input[i] === '&'
      if (isFdDup) i += 1
      while (i < input.length && (input[i] === ' ' || input[i] === '\t')) i += 1
      readWord(isFdDup ? 'discard' : 'redirect')
      continue
    }
    if (op === '<') {
      i += 1
      let isReadWrite = false
      if (input[i] === '<') {
        i += 1
        if (input[i] === '<' || input[i] === '-') i += 1
      } else if (input[i] === '&') {
        i += 1
      } else if (input[i] === '>') {
        isReadWrite = true
        i += 1
      }
      while (i < input.length && (input[i] === ' ' || input[i] === '\t')) i += 1
      readWord(isReadWrite ? 'redirect' : 'discard')
      continue
    }
    readWord('command')
  }
  flush()
  while (stack.length > 0) {
    const frame = stack.pop()!
    current = frame.current
    flush()
  }
  return { commands, redirects, nested }
}

function collectShellTargets(initialInput: string, out: string[]): void {
  const queue: string[] = [initialInput]
  while (queue.length > 0) {
    const input = queue.pop()!
    const { commands, redirects, nested } = scanShell(input)
    for (const words of commands) {
      let idx = 0
      while (idx < words.length) {
        const w = words[idx]!
        if (/^[A-Za-z_]\w*=/.test(w)) {
          idx += 1
          continue
        }
        if (CMD_WRAPPERS.has(w)) {
          idx += 1
          while (idx < words.length && words[idx]!.startsWith('-')) {
            const flag = words[idx]!
            idx += 1
            if (flag === '--') break
            if (wrapperFlagTakesArg(w, flag) && idx < words.length) idx += 1
          }
          continue
        }
        break
      }
      if (idx >= words.length) continue
      const cmd = stripQuotes(words[idx]!).replace(/^\\/, '').replace(/^.*\//, '')
      const args = words.slice(idx + 1)

      if (cmd === 'sed') {
        let inPlace = false
        let hasFlagScript = false
        let needScript = true
        const targets: string[] = []
        for (let i = 0; i < args.length; i += 1) {
          const w = args[i]!
          if (w === '--') {
            for (i += 1; i < args.length; i += 1) targets.push(stripQuotes(args[i]!))
            break
          }
          if (w === '--expression' || w === '--file' || /^-[a-zA-Z]*[ef]$/.test(w)) {
            if (/^-[a-zA-Z]*i/.test(w)) inPlace = true
            hasFlagScript = true
            needScript = false
            i += 1
            continue
          }
          if (w.startsWith('--expression=') || w.startsWith('--file=') || /^-[a-zA-Z]*[ef].+/.test(w)) {
            if (/^-[a-zA-Z]*i/.test(w)) inPlace = true
            hasFlagScript = true
            needScript = false
            continue
          }
          if (w === '--in-place' || w.startsWith('--in-place=')) {
            inPlace = true
            continue
          }
          if (/^-[a-zA-Z]*i/.test(w)) {
            inPlace = true
            // BSD/macOS `sed -i '' 's/a/b/' file` passes an empty backup suffix as the next argument.
            if (/^-[a-zA-Z]*i$/.test(w) && (args[i + 1] === "''" || args[i + 1] === '""')) i += 1
            continue
          }
          if (w.startsWith('-')) continue
          if (needScript && !hasFlagScript) {
            needScript = false
            continue
          }
          targets.push(stripQuotes(w))
        }
        if (inPlace) out.push(...targets)
      } else if (cmd === 'perl') {
        let hasP = false
        let hasI = false
        let hasFlagScript = false
        const targets: string[] = []
        for (let i = 0; i < args.length; i += 1) {
          const w = args[i]!
          if (w === '--') {
            for (i += 1; i < args.length; i += 1) targets.push(stripQuotes(args[i]!))
            break
          }
          if (w === '-e' || w === '-E') {
            hasFlagScript = true
            i += 1
            continue
          }
          if (w.startsWith('-e') || w.startsWith('-E')) {
            hasFlagScript = true
            continue
          }
          if (w.startsWith('-') && w.length > 1) {
            const flags = /^-[a-zA-Z]+/.exec(w)?.[0] ?? ''
            if (flags.includes('p')) hasP = true
            if (flags.includes('i')) hasI = true
            if (flags.includes('e') || flags.includes('E')) {
              hasFlagScript = true
              if (/^-[a-zA-Z]*[eE]$/.test(w)) i += 1
            }
            continue
          }
          if (!hasFlagScript) {
            hasFlagScript = true
            continue
          }
          targets.push(stripQuotes(w))
        }
        if (hasP && hasI) out.push(...targets)
      } else if (cmd === 'tee') {
        for (let i = 0; i < args.length; i += 1) {
          const w = args[i]!
          if (w === '--') {
            for (i += 1; i < args.length; i += 1) out.push(stripQuotes(args[i]!))
            break
          }
          if (!w.startsWith('-')) out.push(stripQuotes(w))
        }
      } else if (PWSH_WRITE_RE.test(cmd)) {
        const named = args.findIndex(w => /^-(?:path|filepath|literalpath)$/i.test(w))
        const target = named !== -1 ? args[named + 1] : args.find(w => !w.startsWith('-'))
        if (target !== undefined) out.push(stripQuotes(target))
      }
    }
    out.push(...redirects)
    for (let i = nested.length - 1; i >= 0; i -= 1) queue.push(nested[i]!)
  }
}

/** Targets of in-place shell edits: `sed -i … file`, `perl -pi … file`, `> file`, `tee file`. */
export function shellEditTargets(command: string): string[] {
  const out: string[] = []
  collectShellTargets(command, out)
  return out.filter(p => p !== '' && p !== '/dev/null' && !/^\$null$/i.test(p) && !p.startsWith('&')).map(p => p.replaceAll('\\', '/'))
}

export function apply(ctx: Context, config: Config): void {
  const pending = new Set<string>()
  const remember = (key: string): void => {
    pending.add(key)
    if (pending.size > 200) pending.delete(pending.values().next().value!)
  }
  const MANIFESTS = ['package.json', 'Cargo.toml', 'go.mod', 'composer.json', 'Gemfile', 'pyproject.toml', 'setup.py', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'deno.json', 'mix.exs', 'pubspec.yaml']
  const optionsFor = (cfg: Config, workspace: string) => ({
    extraGlobs: cfg.extraGlobs,
    ignore: cfg.ignore,
    defaultGlobs: cfg.defaultGlobs,
    headerLines: cfg.headerLines,
    isProjectRoot: (dir: string) => dir === '' || MANIFESTS.some(m => existsSync(join(workspace, dir, m))),
  })

  const check = async (cfg: Config, path: string, workspace: string): Promise<{ relative: string; info: GeneratedInfo } | undefined> => {
    const { absolute, relative } = resolvePath(path, workspace)
    if (relative.startsWith('../') && !relative.includes('node_modules/')) return undefined
    const content = await readExisting(absolute, cfg.maxFileBytes)
    const info = generatedInfo(relative, content, optionsFor(cfg, workspace))
    return info === undefined ? undefined : { relative, info }
  }

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>) => {
    const cfg = resolveConfig(config)
    const workspace = workspaceOf(exec)
    let hit: { relative: string; info: GeneratedInfo } | undefined
    if (cfg.shellTools.includes(exec.name)) {
      if (!cfg.guardShell) return next()
      const command = (exec.arguments as { command?: unknown } | null)?.command
      if (typeof command !== 'string') return next()
      for (const target of shellEditTargets(command)) {
        hit = await check(cfg, target, workspace)
        if (hit !== undefined) break
      }
    } else {
      const mutation = fileMutation(exec)
      if (mutation === undefined) return next()
      hit = await check(cfg, mutation.path, workspace)
    }
    if (hit === undefined) return next()
    const key = createHash('sha256').update(`${exec.name}\0${workspace}\0${canonicalJson(exec.arguments)}`).digest('hex')
    if (cfg.allowIdenticalRetry && pending.delete(key)) return next()
    const retryAllowed = cfg.mode === 'deny' && cfg.allowIdenticalRetry
    const text = denialText(hit.relative, hit.info, retryAllowed)
    if (cfg.mode === 'ask') {
      return { kind: 'ask', reason: text, displayReason: { en: `${hit.relative} is a generated file. ${hit.info.hint}.` } }
    }
    if (retryAllowed) remember(key)
    return { kind: 'deny', reason: text }
  })
}
