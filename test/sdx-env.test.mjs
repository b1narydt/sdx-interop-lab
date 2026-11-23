// LAB_SELF_TEST_ONLY: the Node.js oracle (src/sdx/env.mjs) reproduces every VA-ENV and VA-SIG
// outcome, including the laboratory refusal detail; the write checks fail exactly where each
// write-check qualification sample says; and the oracle's LZMA decoder (src/sdx/lzma.mjs) reads
// streams from two encoders and tells whether an end-of-stream marker was written.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { REFUSAL_CLASSES, checkWrite, runCase } from '../src/sdx/env.mjs'
import { LzmaError, decodeAlone } from '../src/sdx/lzma.mjs'

const read = rel => JSON.parse(fs.readFileSync(new URL(`../${rel}`, import.meta.url)))
const PROFILE = read('fixtures/sdx/v1/deployment-profile.json')
const SUITES = { 'VA-ENV': read('fixtures/sdx/v1/va-env/vectors.json'), 'VA-SIG': read('fixtures/sdx/v1/va-sig/vectors.json') }

for (const [name, suite] of Object.entries(SUITES)) {
  test(`LAB_SELF_TEST_ONLY: ${name} — every case reproduces under the Node oracle`, () => {
    assert.equal(suite.claim, 'LAB_SELF_TEST_ONLY')
    assert.equal(suite.profile.id, 'tpnil-sdx-lab:v1')
    assert.equal(suite.caseCount, suite.cases.length)
    for (const c of suite.cases) {
      assert.ok(['required', 'labChoice'].includes(c.tag), c.id)
      const result = runCase(PROFILE, c)
      assert.ok(result.ok, `${c.id} ${c.title}: ${result.failures.join('; ')}`)
      if (c.expect.verdict === 'refused') {
        assert.ok(REFUSAL_CLASSES.includes(c.expect.refusal.class), c.id)
        assert.equal(result.actual.refusal.detail, c.expect.refusal.detail, `${c.id} refused for another rule`)
      }
    }
  })

  test(`LAB_SELF_TEST_ONLY: ${name} — the write checks fail exactly where each qualification sample says`, () => {
    const byId = Object.fromEntries(suite.cases.map(c => [c.id, c]))
    assert.ok(suite.writeCheckQualification.length > 0)
    for (const sample of suite.writeCheckQualification) {
      const failing = checkWrite(PROFILE, byId[sample.writeCase], sample.envelope).filter(r => !r.ok).map(r => r.check).sort()
      assert.deepEqual(failing, sample.failingChecks, sample.title)
    }
  })
}

test('LAB_SELF_TEST_ONLY: the oracle LZMA decoder reads LZMA-JS and liblzma alone streams and reports the end-of-stream marker', () => {
  const text = 'hello hello hello hello world, LAB_SELF_TEST_ONLY'
  const head = '5d000000023100000000000000'
  const body = '00341949ee8de9560c612a6f6bd30ac25b89862ae4ae47fcebee4946b342fe7bb4e4'
  // LZMA-JS 2.3.2, mode 9, disableEndMark: the size in the header and no marker.
  const noMarker = decodeAlone(Buffer.from(`${head}${body}db033384`, 'hex'))
  assert.equal(Buffer.from(noMarker.output).toString(), text)
  assert.equal(noMarker.marker, false)
  assert.equal(noMarker.declaredSize, text.length)
  assert.equal(noMarker.dictionarySize, 1 << 25)
  // LZMA-JS with its default marker.
  const marked = decodeAlone(Buffer.from(`${head}${body}deaaf720fffeaef000`, 'hex'))
  assert.equal(Buffer.from(marked.output).toString(), text)
  assert.equal(marked.marker, true)
  // liblzma (Python lzma, FORMAT_ALONE, preset 9): unknown size, a 64 MiB dictionary, the marker.
  const lib = decodeAlone(Buffer.from(`5d00000004ffffffffffffffff${body}deaaf720fffeaef000`, 'hex'))
  assert.equal(Buffer.from(lib.output).toString(), text)
  assert.equal(lib.declaredSize, null)
  assert.equal(lib.marker, true)
  const code = hex => { try { decodeAlone(Buffer.from(hex, 'hex')); return null } catch (error) { assert.ok(error instanceof LzmaError); return error.code } }
  assert.equal(code(`${head}${body}db0333`), 'truncated')
  assert.equal(code(`${head}${body}db03338400`), 'trailing-bytes')
  assert.equal(code(`${head}ff${body.slice(2)}db033384`), 'corrupt')
  assert.equal(code('e1000000023100000000000000'), 'properties')
})
