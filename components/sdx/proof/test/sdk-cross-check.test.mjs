// Re-verifies the committed VA-ANC fixtures with @bsv/sdk and cborg, without any generator
// code: the merkle root of every cited and walked transaction, the BEEF of every accepted
// reference and walk row, the commitment key of every walked entry, the deterministic encoding
// of every reference and the synthetic headers. Also confirms that generation is reproducible.

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { Beef, Hash, KeyDeriver, PrivateKey, PushDrop, Transaction } from '@bsv/sdk'
import * as cborg from 'cborg'

const ROOT = new URL('../../../../', import.meta.url)
const VA_ANC = JSON.parse(fs.readFileSync(new URL('fixtures/sdx/v1/va-anc/vectors.json', ROOT)))
const PROFILE = JSON.parse(fs.readFileSync(new URL('fixtures/sdx/v1/deployment-profile.json', ROOT)))
const references = VA_ANC.cases.filter(c => c.verifier === 'reference')
const display = bytes => Buffer.from(bytes).reverse().toString('hex')
const sha256d = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest()
const roots = new Map(VA_ANC.chain.headers.map(({ height, header }) => [height, display(Buffer.from(header, 'hex').subarray(36, 68))]))
const tracker = { isValidRootForHeight: async (root, height) => roots.get(height) === root, currentHeight: async () => VA_ANC.chain.tipHeight }

function decode(hex) {
  try { return cborg.decode(Buffer.from(hex, 'hex'), { useMaps: true, strict: true, rejectDuplicateMapKeys: true }) } catch { return null }
}

// The merkle-root check of ANC §6.1 steps 1-3, by @bsv/sdk: null when the BEEF or the cited
// transaction's BUMP cannot be read.
function sdkRootAccepted(beefBytes, txid) {
  let beef
  try { beef = Beef.fromBinary([...beefBytes]) } catch { return null }
  const bump = beef.findBump(txid)
  if (!bump) return null
  try { return bump.computeRoot(txid) === roots.get(bump.blockHeight) } catch { return false }
}

test('LAB_SELF_TEST_ONLY: @bsv/sdk agrees with the checker on the merkle root of every cited transaction', () => {
  let compared = 0
  for (const item of references) {
    const reference = decode(item.input.reference)
    const { result, label } = item.expected
    if (!reference) { assert.equal(result, 'REJECT', `${item.id}: cborg cannot read the reference`); continue }
    const accepted = sdkRootAccepted(reference.get('beef'), display(reference.get('tx')))
    if (result === 'ACCEPT') assert.equal(accepted, true, item.id)
    if (label === 'block-root-mismatch') assert.equal(accepted, false, item.id)
    if (accepted !== null) compared++
  }
  assert.ok(compared >= 10, `${compared} roots compared`)
})

test('LAB_SELF_TEST_ONLY: every accepted reference and every walk row is a valid BEEF for @bsv/sdk', async () => {
  const beefs = [
    ...references.filter(c => c.expected.result === 'ACCEPT').map(c => [c.id, Buffer.from(decode(c.input.reference).get('beef'))]),
    ...Object.entries(VA_ANC.transactions).filter(([name]) => name !== 'M3-bump-altered').map(([name, row]) => [name, Buffer.from(row.beef, 'hex')])
  ]
  for (const [id, beef] of beefs) {
    if (beef.subarray(0, 4).every(b => b === 1)) assert.equal(Transaction.fromAtomicBEEF([...beef]).id('hex'), display(beef.subarray(4, 36)), id)
    const parsed = Beef.fromBinary([...beef])
    assert.equal(parsed.isValid(false), true, id)
    assert.equal(await parsed.verify(tracker, false), true, id)
  }
  const altered = Beef.fromBinary([...Buffer.from(VA_ANC.transactions['M3-bump-altered'].beef, 'hex')])
  assert.equal(await altered.verify(tracker, false), false)
})

test('LAB_SELF_TEST_ONLY: @bsv/sdk derives the commitment key of every participant entry from the published root', async () => {
  const words = PROFILE.derivation.keyPath.keywords
  const protocolID = PROFILE.recordKeyIdentifiers.commitment.protocolID
  const seedOf = root => {
    const prk = Hash.sha256hmac(new Array(32).fill(0), [...Buffer.from(root, 'hex')])
    return Buffer.from(Hash.sha256hmac(prk, [...Buffer.from(PROFILE.derivation.curveLabels.secp256k1, 'ascii'), 1])).toString('hex')
  }
  let checked = 0
  for (const [name, row] of Object.entries(VA_ANC.transactions)) {
    const chainName = name.match(/^[A-Z]+/)[0]
    const chain = VA_ANC.chains[chainName]
    const action = VA_ANC.actions[name]
    if (!chain || !action || row.entryOutput === null || name === 'S1' || name === 'W1' || name === 'E1' || name === 'D1') continue
    const tx = Transaction.fromAtomicBEEF([...Buffer.from(row.beef, 'hex')])
    const decoded = PushDrop.decode(tx.outputs[row.entryOutput].lockingScript, 'after')
    const deriver = new KeyDeriver(PrivateKey.fromHex(seedOf(VA_ANC.testKeys.roots.participant[String(action.ep)].root)))
    const keyID = `${words.level1}/${chain.accountId}/${words.level2}/${chain.runtimeId}/${words.level3}/${action.aid}`
    assert.equal(decoded.lockingPublicKey.toString(), deriver.derivePublicKey(protocolID, keyID, 'self', true).toString(), name)
    checked++
  }
  assert.ok(checked >= 14, `${checked} keys checked`)
})

test('LAB_SELF_TEST_ONLY: cborg re-encodes every deterministic reference byte for byte', () => {
  for (const item of references) {
    const bytes = Buffer.from(item.input.reference, 'hex')
    const reference = decode(item.input.reference)
    if (!reference) continue
    const again = Buffer.from(cborg.encode(reference, cborg.rfc8949EncodeOptions))
    if (item.expected.label === 'reference-not-deterministic') assert.notDeepEqual(again, bytes, item.id)
    else assert.deepEqual(again, bytes, item.id)
  }
})

test('LAB_SELF_TEST_ONLY: the synthetic headers carry valid regtest proof of work and link', () => {
  let previous = null
  for (const { header } of VA_ANC.chain.headers) {
    const bytes = Buffer.from(header, 'hex')
    const hash = sha256d(bytes)
    const bits = bytes.readUInt32LE(72)
    const target = BigInt(bits & 0x7fffff) << BigInt(8 * ((bits >>> 24) - 3))
    assert.ok(BigInt(`0x${display(hash)}`) <= target)
    if (previous) assert.ok(bytes.subarray(4, 36).equals(previous))
    previous = hash
  }
})

test('LAB_SELF_TEST_ONLY: regeneration reproduces the committed fixtures exactly', () => {
  execFileSync(process.execPath, ['generate.mjs', '--check'], { cwd: new URL('../', import.meta.url), stdio: 'pipe' })
})
