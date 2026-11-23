// LAB_SELF_TEST_ONLY qualification of the SDX harness (src/sdx/harness/): driven by a qualification
// driver that answers the suites' own expectations, every runnable case passes, in every cell of the
// matrix; answered wrongly, the cases fail; unanswered, they are blocked; answered with garbage, they
// are errors. The comparison and contract-gap rules are checked directly.
import test from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { Harness, aggregate, mergeRepetitions, summarise } from '../src/sdx/harness/run.mjs'
import { compareKey, compareRead } from '../src/sdx/harness/compare.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const ECHO = path.join(ROOT, 'src/sdx/harness/echo-driver.mjs')
const RUNNABLE = ['VA-ENV', 'VA-SIG', 'VA-KEY', 'VA-ADM']

const echo = (id, mode, declaration = {}) => ({
  id,
  declaration: { writeOptions: { random: true, convergent: true, writerBlind: true }, containedKeys: false, ...declaration },
  driver: { argv: [process.execPath, ECHO], cwd: ROOT, env: { ECHO_MODE: mode } }
})
const outcomes = list => new Set(list.map(r => r.outcome))

test('LAB_SELF_TEST_ONLY: answered with the published expectations, every runnable case passes in every cell', async () => {
  const harness = new Harness({ root: ROOT, suts: [echo('a', 'expected'), echo('b', 'expected')], concurrency: 8 })
  const run = mergeRepetitions([await harness.repetition()])
  for (const sut of ['a', 'b']) {
    for (const suite of RUNNABLE) {
      const bad = run.suites[sut][suite].filter(r => r.outcome !== 'PASS')
      assert.deepEqual(bad, [], `${sut} ${suite}`)
    }
    for (const suite of ['VA-ENC', 'VA-ANC']) assert.deepEqual(outcomes(run.suites[sut][suite]), new Set(['BLOCKED']))
  }
  assert.equal(run.matrix.length, 4)
  for (const cell of run.matrix) {
    assert.equal(cell.cases.length, 15)
    assert.equal(summarise(cell.cases).aggregate, 'PASS', `${cell.writer}->${cell.reader}`)
  }
})

test('LAB_SELF_TEST_ONLY: answered wrongly, the cases fail; unanswered, blocked; unreadable, errors', async () => {
  const flipped = mergeRepetitions([await new Harness({ root: ROOT, suts: [echo('f', 'flip')], concurrency: 8 }).repetition()])
  for (const suite of RUNNABLE) {
    for (const r of flipped.suites.f[suite]) assert.ok(r.outcome === 'FAIL' || (r.tag === 'labChoice' && r.outcome === 'INCONCLUSIVE'), `${r.id}: ${r.outcome} ${r.reason}`)
  }
  const blocked = mergeRepetitions([await new Harness({ root: ROOT, suts: [echo('u', 'unsupported')], concurrency: 8 }).repetition()])
  for (const suite of RUNNABLE) assert.deepEqual(outcomes(blocked.suites.u[suite]), new Set(['BLOCKED']), suite)
  assert.deepEqual(outcomes(blocked.matrix[0].cases), new Set(['BLOCKED']))
  const garbage = mergeRepetitions([await new Harness({ root: ROOT, suts: [echo('g', 'garbage')], concurrency: 8 }).repetition()])
  for (const suite of RUNNABLE) assert.deepEqual(outcomes(garbage.suites.g[suite]), new Set(['ERROR']), suite)
})

test('LAB_SELF_TEST_ONLY: comparison rules of the driver contract', () => {
  const accepted = { tier: 'nothing', verdict: 'accepted', aid: 'A', fields: [{ n: 'm', sn: 'pu', state: 'value', value: { b: 1, a: 2 } }] }
  // JSON objects compare by member name; added members are not judged.
  assert.equal(compareRead(accepted, { ...accepted, extra: 1, fields: [{ n: 'm', sn: 'pu', state: 'value', value: { a: 2, b: 1 } }] }), null)
  assert.match(compareRead(accepted, { ...accepted, hdr: { f: 'x' } }), /hdr present/)
  // A refusal compares by verdict, and by class only where the class is required.
  const refused = { verdict: 'refused', refusal: { class: 'integrity', detail: 'lab-label' } }
  assert.equal(compareRead(refused, { verdict: 'refused', refusal: { class: 'integrity', detail: 'other words' } }), null)
  assert.match(compareRead(refused, { verdict: 'refused', refusal: { class: 'decode' } }), /refusal class/)
  assert.equal(compareRead(refused, { verdict: 'refused', refusal: { class: 'decode' } }, 'labChoice'), null)
  // Contained keys: split as the seeds' public keys; derive without the private key.
  const seeds = { secp256k1Seed: '00'.repeat(31) + '01', p256Seed: '00'.repeat(31) + '01' }
  const g = { secp256k1Public: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', p256Public: '036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' }
  assert.equal(compareKey(seeds, g, { op: 'split' }, { contained: true }).diff, null)
  assert.match(compareKey(seeds, g, { op: 'split' }).diff, /seeds/)
  const derived = { identifier: 'i', publicKey: 'p', privateKey: 'k' }
  assert.equal(compareKey(derived, { identifier: 'i', publicKey: 'p' }, { op: 'derive' }, { contained: true }).diff, null)
  assert.match(compareKey(derived, { identifier: 'i', publicKey: 'p' }, { op: 'derive' }).diff, /privateKey missing/)
  assert.equal(aggregate(['PASS', 'NOT_APPLICABLE', 'BLOCKED']), 'BLOCKED')
  assert.equal(aggregate(['PASS', 'INCONCLUSIVE', 'FAIL']), 'FAIL')
  assert.equal(aggregate(['NOT_APPLICABLE']), 'NOT_APPLICABLE')
})

test('LAB_SELF_TEST_ONLY: a declared contract gap blocks, and never passes or fails, the difference it explains', () => {
  const harness = new Harness({ root: ROOT, suts: [] })
  const gaps = { revision: 'contract v0', missingProjectionMembers: ['hdr'], missingFieldMembers: ['filename'], refusalVocabulary: ['malformed', 'signature'] }
  const sut = { declaration: { contractGaps: gaps } }
  const kase = { tag: 'required', expect: { tier: 'audit', verdict: 'accepted', aid: 'A', hdr: { f: 'x' }, fields: [{ n: 'd', sn: 'pr', state: 'value', value: 1, filename: 'f' }], signature: { kid: 'k', shape: 'current' } } }
  const { hdr, ...noHdr } = kase.expect
  const lacking = { ...noHdr, fields: [{ n: 'd', sn: 'pr', state: 'value', value: 1 }] }
  assert.equal(harness.judgeRead(kase, { value: lacking }, sut).outcome, 'BLOCKED')
  assert.equal(harness.judgeRead(kase, { value: { ...lacking, aid: 'B' } }, sut).outcome, 'FAIL')
  assert.equal(harness.judgeRead(kase, { value: lacking }, {}).outcome, 'FAIL')
  const refusal = { tag: 'required', expect: { verdict: 'refused', refusal: { class: 'root-pk-mismatch' } } }
  assert.equal(harness.judgeRead(refusal, { value: { verdict: 'refused', refusal: { class: 'signature' } } }, sut).outcome, 'BLOCKED')
  assert.equal(harness.judgeRead(refusal, { value: { verdict: 'refused', refusal: { class: 'signature' } } }, {}).outcome, 'FAIL')
  assert.equal(harness.judgeRead(refusal, { value: { verdict: 'accepted', tier: 'nothing', aid: 'A', fields: [] } }, sut).outcome, 'FAIL')
})
