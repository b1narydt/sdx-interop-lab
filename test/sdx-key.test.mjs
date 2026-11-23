// LAB_SELF_TEST_ONLY: the Node.js oracle (src/sdx/keys.mjs) reproduces every VA-KEY known answer
// under the laboratory deployment profile (KEYS §1.12 items 1-3 and 5-11; item 4 is VA-SIG's).
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { runCase } from '../src/sdx/keys.mjs'

const read = rel => JSON.parse(fs.readFileSync(new URL(`../${rel}`, import.meta.url)))
const PROFILE = read('fixtures/sdx/v1/deployment-profile.json')
const VA_KEY = read('fixtures/sdx/v1/va-key/vectors.json')

test('LAB_SELF_TEST_ONLY: VA-KEY — every known answer reproduces under the Node oracle', () => {
  assert.equal(VA_KEY.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(VA_KEY.caseCount, VA_KEY.cases.length)
  for (const c of VA_KEY.cases) {
    const result = runCase(PROFILE, c)
    assert.ok(result.ok, `${c.id} ${c.title}: ${JSON.stringify(result.actual)}`)
  }
  assert.deepEqual([...new Set(VA_KEY.cases.map(c => c.item))].sort((a, b) => a - b), [1, 2, 3, 5, 6, 7, 8, 9, 10, 11])
})
