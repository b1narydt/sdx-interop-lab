// Optional third oracle: the repository's Rust participant (components/rust, built from
// bsv-blockchain/rs-sdk with `cargo build --locked`). Set TPNIL_RUST_PARTICIPANT to its
// binary to run; otherwise the test is skipped.

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { Beef, BEEF_V1, MerklePath } from '@bsv/sdk'
import * as cborg from 'cborg'

const BINARY = process.env.TPNIL_RUST_PARTICIPANT
const ROOT = new URL('../../../../', import.meta.url)
const VA_ANC = JSON.parse(fs.readFileSync(new URL('fixtures/sdx/v1/va-anc/vectors.json', ROOT)))
const display = bytes => Buffer.from(bytes).reverse().toString('hex')

function participant(commands) {
  return JSON.parse(execFileSync(BINARY, { input: JSON.stringify(commands), maxBuffer: 64 * 1024 * 1024 }))
}

test('LAB_SELF_TEST_ONLY: the Rust participant agrees on BEEF parsing and the merkle root of every accepted reference', { skip: BINARY ? false : 'TPNIL_RUST_PARTICIPANT is not set' }, t => {
  const roots = new Map(VA_ANC.chain.headers.map(({ height, header }) => [height, display(Buffer.from(header, 'hex').subarray(36, 68))]))
  const commands = []
  const expectations = []
  for (const item of VA_ANC.cases.filter(c => c.verifier === 'reference' && c.expected.result === 'ACCEPT')) {
    const proof = cborg.decode(Buffer.from(item.input.reference, 'hex'), { useMaps: true, strict: true })
    const beef = Beef.fromBinary([...proof.get('beef')])
    const txid = display(proof.get('tx'))
    const bump = beef.findBump(txid)
    const v1 = new Beef(BEEF_V1)
    v1.mergeRawTx(beef.findTxid(txid).tx.toBinary(), v1.mergeBump(MerklePath.fromBinary(bump.toBinary())))
    commands.push({ op: 'beef', hex: Buffer.from(v1.toBinary()).toString('hex'), txid })
    expectations.push({ id: item.id, root: roots.get(bump.blockHeight) })
  }
  const responses = participant(commands)
  assert.equal(responses.length, expectations.length)
  responses.forEach((response, i) => {
    const want = expectations[i]
    assert.equal(response.ok, true, `${want.id}: ${response.error}`)
    assert.equal(response.result.valid, true, want.id)
    assert.equal(response.result.root, want.root, want.id)
  })
  assert.ok(expectations.length >= 4)
  t.diagnostic(`${expectations.length} merkle roots agree with the Rust participant`)
})
