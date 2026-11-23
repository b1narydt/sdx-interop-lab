import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { ChainDataError, bumpRoot, checkContainer, createHeaderTracker, displayHex, evaluateSpend, isMinimalPush, parseBeef, parseBump, parseScript } from '../src/sdx/tx.mjs'
import { AncError, DEAD_LETTER_CLASSES, commitmentDerivationIdentifier, commitmentKey, decodeStandIn, runSuiteCase, secp256k1Seed, selfDerivedPublicKey, suiteTracker, verifyReference } from '../src/sdx/anc.mjs'

const read = rel => JSON.parse(fs.readFileSync(new URL(`../${rel}`, import.meta.url)))
const VA_ANC = read('fixtures/sdx/v1/va-anc/vectors.json')
const PROFILE = read('fixtures/sdx/v1/deployment-profile.json')
const h = value => Buffer.from(value, 'hex')
const code = fn => { try { fn(); return null } catch (error) { return error.code ?? String(error) } }

function assertStrictJson(value, where = '$') {
  if (typeof value === 'number') assert.ok(Number.isSafeInteger(value), `${where} is not an integer`)
  else if (Array.isArray(value)) value.forEach((item, i) => assertStrictJson(item, `${where}[${i}]`))
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) assertStrictJson(v, `${where}.${k}`)
}

test('LAB_SELF_TEST_ONLY: BUMP roots and a mainnet P2PKH spend from the published BRC-74 and BRC-62 examples', () => {
  // BRC-74 example: block 813706, three level-0 hashes, published root 57aab6e6...b483b4.
  const bump = parseBump(h('fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b010001fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4'))
  assert.equal(bump.blockHeight, 813706)
  for (const txid of ['304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711', 'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00', '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e']) {
    assert.equal(displayHex(bumpRoot(bump, h(txid).reverse())), '57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4')
  }
  assert.equal(code(() => bumpRoot(bump, Buffer.alloc(32))), 'bump-txid-absent')
  // BRC-62 example: a mainnet parent with its BUMP and a child that spends it by P2PKH.
  const beef = parseBeef(h('0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000'))
  const [parent, child] = beef.order.map(key => beef.txs.get(key))
  assert.equal(displayHex(parent.tx.txid), '3ecead27a44d013ad1aae40038acbb1883ac9242406808bb4667c15b4f164eac')
  assert.equal(beef.bumps[parent.bumpIndex].blockHeight, 814435)
  const spend = (tx, prevOutput = parent.tx.outputs[0]) => evaluateSpend({ tx, inputIndex: 0, prevTxid: parent.tx.txid, prevOut: 0, prevOutput })
  assert.deepEqual(spend(child.tx), { result: 'PASS', reason: null, template: 'p2pkh' })
  // The signature commits to the spent value and to the outputs.
  assert.equal(spend(child.tx, { ...parent.tx.outputs[0], satoshis: parent.tx.outputs[0].satoshis + 1 }).reason, 'spends-signature-invalid')
  const changed = { ...child.tx, outputs: [{ ...child.tx.outputs[0], raw: Buffer.concat([Buffer.from([0x3d]), child.tx.outputs[0].raw.subarray(1)]) }] }
  assert.equal(spend(changed).reason, 'spends-signature-invalid')
})

test('LAB_SELF_TEST_ONLY: minimal pushes and the ANC §2 container shape', () => {
  assert.equal(isMinimalPush(parseScript(h('4c03010203')).chunks[0]), false)
  assert.equal(isMinimalPush(parseScript(h('03010203')).chunks[0]), true)
  assert.equal(isMinimalPush(parseScript(h('0105')).chunks[0]), false)
  assert.equal(isMinimalPush(parseScript(h('0181')).chunks[0]), false)
  assert.equal(parseScript(h('6a05aabb')).malformed, true)
  const key = `21${'02'}${'11'.repeat(32)}`
  assert.deepEqual(checkContainer(h(`03aabbcc75${key}ac`)).ok, true)
  assert.equal(checkContainer(h(`4c03aabbcc75${key}ac`)).reason, 'container-push-not-minimal')
  assert.equal(checkContainer(h(`03aabbcc01dd6d${key}ac`)).reason, 'container-field-count')
  assert.equal(checkContainer(h(`${key}ac03aabbcc75`)).reason, 'container-template')
  assert.equal(checkContainer(h(`${key}ac`)).reason, 'container-template')
  assert.equal(checkContainer(h(`03aabbcc75${key}`)).reason, 'container-template')
  assert.equal(checkContainer(h('03aabb')).reason, 'container-script-malformed')
})

test('LAB_SELF_TEST_ONLY: BEEF and header-list refusals', () => {
  const atomic = h(VA_ANC.transactions.M1.beef)
  const plain = atomic.subarray(36)
  assert.equal(parseBeef(atomic).atomic, true)
  assert.equal(parseBeef(plain).atomic, false)
  const err = bytes => { try { parseBeef(bytes); return null } catch (error) { assert.ok(error instanceof ChainDataError); return error.code } }
  assert.equal(err(Buffer.concat([plain, Buffer.from([0])])), 'trailing-bytes')
  assert.equal(err(Buffer.concat([Buffer.from('0200beef', 'hex'), plain.subarray(4)])), 'beef-v2-unsupported')
  assert.equal(err(Buffer.concat([Buffer.from('0300beef', 'hex'), plain.subarray(4)])), 'beef-version')
  assert.equal(err(Buffer.concat([atomic.subarray(0, 4), Buffer.alloc(32), atomic.subarray(36)])), 'beef-atomic-subject-absent')
  assert.equal(err(plain.subarray(0, plain.length - 3)), 'truncated')
  const headers = VA_ANC.chain.headers
  const tracker = createHeaderTracker(headers)
  assert.equal(tracker.tipHeight, VA_ANC.chain.tipHeight)
  const first = tracker.headerAt(101)
  assert.equal(tracker.isValidRootForHeight(first.merkleRoot, 101), true)
  assert.equal(tracker.isValidRootForHeight(first.merkleRoot, 102), false)
  assert.equal(suiteTracker(VA_ANC, 101).headerAt(102), null)
  const altered = headers.map(e => ({ ...e }))
  altered[50].header = altered[50].header.slice(0, 80) + (altered[50].header[80] === '0' ? '1' : '0') + altered[50].header.slice(81)
  assert.ok(['header-link', 'header-pow'].includes(code(() => createHeaderTracker(altered))))
  assert.equal(code(() => createHeaderTracker([headers[0], headers[2]])), 'header-gap')
  assert.equal(code(() => createHeaderTracker([])), 'header-empty')
})

test('LAB_SELF_TEST_ONLY: commitment keys follow the published laboratory profile', () => {
  assert.equal(VA_ANC.profile.id, PROFILE.profile)
  assert.equal(VA_ANC.profile.path, 'fixtures/sdx/v1/deployment-profile.json')
  // The KEYS §1.8.1 worked-example identifiers, under the profile's signing namespace and keyword.
  const M0 = VA_ANC.actions.M0
  assert.equal(M0.aid, '01JB8ZK3QN7T4YVX2C9M5RDPWA')
  assert.equal(commitmentDerivationIdentifier(PROFILE, '3MNQpxFAsp', '8kRt2wVbZq', M0.aid), '2-sdx sign-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN7T4YVX2C9M5RDPWA')
  const root = h(VA_ANC.testKeys.roots.participant['0'].root)
  const tx = parseBeef(h(VA_ANC.transactions.M0.beef))
  const output = [...tx.txs.values()][0].tx.outputs[VA_ANC.transactions.M0.entryOutput]
  assert.deepEqual(checkContainer(output.script).commitmentKey, commitmentKey(PROFILE, root, '3MNQpxFAsp', '8kRt2wVbZq', M0.aid))
  assert.equal(code(() => secp256k1Seed(Buffer.alloc(32), 'sdx-secp256k1')), 'root-length')
  assert.equal(selfDerivedPublicKey(secp256k1Seed(root, 'sdx-secp256k1'), 'x').length, 33)
  assert.deepEqual(decodeStandIn(Buffer.from('ff', 'hex')), { ok: false, reason: 'record-not-decodable' })
})

test('LAB_SELF_TEST_ONLY: VA-ANC cases reproduce with the suite\'s header list and the published profile', () => {
  assert.equal(VA_ANC.schema, 'tpnil-sdx-vectors@0.1.0')
  assert.equal(VA_ANC.suite, 'VA-ANC')
  assert.equal(VA_ANC.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(VA_ANC.status, 'BASELINE-v0.1')
  assert.deepEqual(VA_ANC.requirements, ['SDX-A-07'])
  assert.deepEqual(VA_ANC.outcomeClasses, DEAD_LETTER_CLASSES)
  for (const citation of VA_ANC.citations) assert.ok(fs.existsSync(new URL(`../${citation.path}`, import.meta.url)), citation.path)
  assert.match(VA_ANC.chain.description, /LAB_SELF_TEST_ONLY/)
  assert.match(VA_ANC.testKeys.warning, /LAB_SELF_TEST_ONLY/)
  assertStrictJson(VA_ANC)
  const ids = VA_ANC.cases.map(c => c.id)
  assert.equal(new Set(ids).size, ids.length)
  const seen = { classes: new Set(), results: new Set() }
  for (const item of VA_ANC.cases) {
    assert.equal(item.requirement, 'SDX-A-07')
    assert.deepEqual(runSuiteCase(VA_ANC, PROFILE, item), item.expected, item.id)
    seen.results.add(`${item.verifier}:${item.expected.result}`)
    if (item.expected.class) seen.classes.add(item.expected.class)
    for (const letter of item.expected.deadLetters ?? []) seen.classes.add(letter.class)
  }
  for (const cls of DEAD_LETTER_CLASSES) assert.ok(seen.classes.has(cls), cls)
  for (const result of ['reference:ACCEPT', 'reference:REJECT', 'reference:INCONCLUSIVE', 'walk:COMPLETE', 'walk:DEAD-LETTERED', 'walk:INCONCLUSIVE']) assert.ok(seen.results.has(result), result)
})

// Byte offsets of a deterministic CBOR item, read independently of the decoder under test.
function itemEnd(bytes, pos) {
  const initial = bytes[pos]
  const major = initial >> 5
  const info = initial & 0x1f
  const width = info < 24 ? 0 : [1, 2, 4, 8][info - 24]
  let n = info < 24 ? info : Number(bytes.readUIntBE(pos + 1, Math.min(width, 6)))
  if (width === 8) n = Number(bytes.readBigUInt64BE(pos + 1))
  let next = pos + 1 + width
  if (major === 2 || major === 3) return next + n
  if (major === 4) { for (let i = 0; i < n; i++) next = itemEnd(bytes, next); return next }
  if (major === 5) { for (let i = 0; i < 2 * n; i++) next = itemEnd(bytes, next); return next }
  return next
}
function topLevelValues(bytes) {
  const values = {}
  let pos = 1
  for (let i = 0; i < (bytes[0] & 0x1f); i++) {
    const keyEnd = itemEnd(bytes, pos)
    const key = bytes.subarray(pos + 1, keyEnd).toString('utf8')
    const valueEnd = itemEnd(bytes, keyEnd)
    values[key] = { from: keyEnd, to: valueEnd }
    pos = valueEnd
  }
  return values
}
// Offsets of the flag byte of every BUMP leaf in a BEEF V1 or Atomic BEEF body.
function bumpFlagOffsets(beef, base) {
  let pos = beef.subarray(0, 4).toString('hex') === '01010101' ? 40 : 4
  const varint = () => { const first = beef[pos]; if (first < 0xfd) { pos += 1; return first } if (first === 0xfd) { pos += 3; return beef.readUInt16LE(pos - 2) } pos += 5; return beef.readUInt32LE(pos - 4) }
  const flags = []
  const bumps = varint()
  for (let b = 0; b < bumps; b++) {
    varint()
    const height = beef[pos++]
    for (let level = 0; level < height; level++) {
      const leaves = varint()
      for (let l = 0; l < leaves; l++) {
        varint()
        flags.push(base + pos)
        pos += beef[pos] === 1 ? 1 : 33
      }
    }
  }
  return flags
}

// Every single-bit change to an accepted reference must leave it unaccepted, except in the
// informational BRC-74 client-txid flag (bit 1 of a BUMP leaf's flag byte) and, for a verifier
// that is not a recipient, in the claimed `aid`. Each listed exception is shown to be unbound.
function mutationSweep(id, { recipient, unboundKeys }) {
  const item = VA_ANC.cases.find(c => c.id === id)
  const tracker = suiteTracker(VA_ANC)
  const reference = h(item.input.reference)
  const verify = bytes => verifyReference({ reference: bytes, tracker, recipient })
  assert.equal(verify(reference).result, 'ACCEPT')
  const values = topLevelValues(reference)
  const info = reference[values.beef.from] & 0x1f
  const beefStart = values.beef.from + 1 + (info < 24 ? 0 : [1, 2, 4, 8][info - 24])
  const flags = new Set(bumpFlagOffsets(reference.subarray(beefStart, values.beef.to), beefStart))
  const ranges = unboundKeys.map(key => ({ key, ...values[key], accepted: 0 }))
  let flagFlips = 0
  for (let offset = 0; offset < reference.length; offset++) {
    for (let bit = 0; bit < 8; bit++) {
      const changed = Buffer.from(reference)
      changed[offset] ^= 1 << bit
      if (verify(changed).result !== 'ACCEPT') continue
      if (bit === 1 && flags.has(offset)) { flagFlips++; continue }
      const range = ranges.find(r => offset >= r.from && offset < r.to)
      assert.ok(range, `${id}: bit ${bit} of reference byte ${offset} changed and the reference still accepts`)
      range.accepted++
    }
  }
  for (const range of ranges) assert.ok(range.accepted > 0, `${id}: ${range.key} is listed as unbound but every change was refused`)
  assert.ok(flagFlips > 0 && flagFlips <= flags.size, `${id}: client-txid flag flips accepted: ${flagFlips}`)
  // Every truncation, and every extension by one byte, is refused with a stated class.
  for (let length = 0; length <= reference.length; length++) {
    const cut = length === reference.length ? Buffer.concat([reference, Buffer.from([0])]) : reference.subarray(0, length)
    const outcome = verify(cut)
    assert.notEqual(outcome.result, 'ACCEPT', `${id}: reference of ${cut.length} bytes`)
    if (outcome.result === 'REJECT') assert.equal(outcome.class, 'cross-ref-invalid')
  }
}

test('LAB_SELF_TEST_ONLY: single-bit mutations of a reference are refused by a recipient, except the informational BUMP flag', () => {
  mutationSweep('VA-ANC-002', { recipient: true, unboundKeys: [] })
})

test('LAB_SELF_TEST_ONLY: for a verifier that is not a recipient, the claimed aid is the one unbound member (ANC §6.1)', () => {
  mutationSweep('VA-ANC-001', { recipient: false, unboundKeys: ['aid'] })
})

test('LAB_SELF_TEST_ONLY: the walk refuses a start it does not hold and an unknown start kind', () => {
  const walk = VA_ANC.cases.find(c => c.id === 'VA-ANC-017')
  const outcome = runSuiteCase(VA_ANC, PROFILE, { ...walk, input: { ...walk.input, rows: ['M1', 'M2'] } })
  assert.equal(outcome.result, 'INCONCLUSIVE')
  assert.equal(outcome.reason, 'start-not-held')
  assert.ok(code(() => runSuiteCase(VA_ANC, PROFILE, { ...walk, input: { ...walk.input, start: { ...walk.input.start, kind: 'midway' } } })) === 'suite-start')
  assert.ok(AncError)
})
