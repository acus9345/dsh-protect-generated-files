import { test } from 'node:test'
import assert from 'node:assert/strict'
import { globToRegExp, matchesAny } from '../src/shared/glob.ts'

test('globToRegExp matches basenames, wildcards, braces, and directory globs', () => {
  assert.equal(globToRegExp('*.pb.go').test('api/v1/user.pb.go'), true)
  assert.equal(globToRegExp('*.pb.go').test('user.pb.go'), true)
  assert.equal(globToRegExp('src/*.{ts,tsx}').test('src/app.tsx'), true)
  assert.equal(globToRegExp('src/*.{ts,tsx}').test('src/sub/app.tsx'), false)
  assert.equal(globToRegExp('dist/').test('dist/a/b.js'), true)
})

test('matchesAny supports negation and ignores blank entries', () => {
  assert.equal(matchesAny('dist/index.js', ['dist/**', '!dist/index.js']), false)
  assert.equal(matchesAny('dist/other.js', ['dist/**', '!dist/index.js']), true)
  assert.equal(matchesAny('src/index.ts', ['', '   ']), false)
  assert.equal(matchesAny('dist/index.js', ['dist/**', '!']), true)
})

test('malformed globs do not throw and never match', () => {
  assert.equal(globToRegExp('').test('src/index.ts'), false)
  assert.equal(globToRegExp('src/{unclosed').test('src/{unclosed'), false)
  assert.equal(globToRegExp('src/[z-a]').test('src/a'), false)
  assert.equal(matchesAny('src/a.ts', ['src/{unclosed', 'src/[z-a]']), false)
})
