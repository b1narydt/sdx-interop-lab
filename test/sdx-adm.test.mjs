// LAB_SELF_TEST_ONLY: the Node.js oracle (src/sdx/adm.mjs) reproduces every VA-ADM admission and
// index outcome (ANC §10-§12) on real SDX v0.1 envelopes in ANC §2.1 containers.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { admissible, runCase } from '../src/sdx/adm.mjs'
import { parseTransaction } from '../src/sdx/tx.mjs'

const read = rel => JSON.parse(fs.readFileSync(new URL(`../${rel}`, import.meta.url)))
const PROFILE = read('fixtures/sdx/v1/deployment-profile.json')
const VA_ADM = read('fixtures/sdx/v1/va-adm/vectors.json')

test('LAB_SELF_TEST_ONLY: VA-ADM — every case reproduces under the Node oracle', () => {
  assert.equal(VA_ADM.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(VA_ADM.caseCount, VA_ADM.cases.length)
  for (const c of VA_ADM.cases) {
    const result = runCase(PROFILE, c)
    assert.ok(result.ok, `${c.id} ${c.title}: step ${result.step}: ${JSON.stringify(result.actual)}`)
  }
})

test('LAB_SELF_TEST_ONLY: VA-ADM — the funding parent carries no record and the gate admits the VA-ENV known-answer envelopes', () => {
  const funding = parseTransaction(Buffer.from(VA_ADM.funding.transaction, 'hex'))
  assert.equal(funding.outputs.filter(o => admissible(PROFILE, o.script)).length, 0)
  const first = parseTransaction(Buffer.from(VA_ADM.cases[0].steps[0].request.tx, 'hex'))
  assert.deepEqual(first.outputs.map(o => admissible(PROFILE, o.script) !== null), [true, false, true])
})
