import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { SECP256K1, accountTag, createWallet, derDecode, derEncode, ecdsaVerify, encodeInput, fromHex, k1Sign, lowS, signDeterministic } from '../src/sdx/p256.mjs'
import { checkVcSdxK1 } from '../src/sdx/k1.mjs'
import { EcError, decodePoint, encodePoint, int32, mod, mulBase, toInt } from '../src/sdx/ec-p256.mjs'
import { deriveChildPublicKey } from '../src/sdx/brc42.mjs'

const vectors = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/vc-sdx-k1/vectors.json', import.meta.url)))
const caseById = (doc, id) => doc.cases.find(entry => entry.id === id)
const failedIds = report => report.failures.map(failure => failure.id)
const mutate = (id, change) => {
  const copy = structuredClone(vectors)
  change(caseById(copy, id), copy)
  return checkVcSdxK1(copy)
}
const flip = text => text.slice(0, -1) + (text.at(-1) === '0' ? '1' : '0')
const walletFor = name => createWallet({ entry: structuredClone(vectors.wallets.entries[name]), profile: vectors.wallets.profile, derivation: vectors.wallets.walletRootDerivation })
const { accountId, secondAccountId } = vectors.profile.identifiers
const name = (operation, role, acct = accountId) => `p sdx ${operation} ${role} ${accountTag(acct)}`

test('LAB_SELF_TEST_ONLY: VC-SDX-K1 vectors pass the independent node:crypto checker', () => {
  const report = checkVcSdxK1(vectors)
  assert.deepEqual(report.failures, [])
  assert.equal(report.cases, 72)
  assert.equal(report.passed, 66)
  assert.equal(report.behavioural, 6)
  assert.deepEqual(vectors.requirements, ['K1-01', 'K1-02', 'K1-03', 'K1-04', 'K1-05'])
  assert.equal(vectors.claim, 'LAB_SELF_TEST_ONLY')
  // Every k1key and k1peer result records the stock BRC-100 call it equals.
  const derivations = vectors.cases.filter(entry => entry.kind === 'module' && /^p sdx k1(key|peer) /.test(entry.request.args.protocolID[1]))
  assert.equal(derivations.length, 14)
  assert.ok(derivations.every(entry => entry.brc100.method === 'getPublicKey' && entry.brc100.publicKey === entry.expected.ciphertext))
})

test('LAB_SELF_TEST_ONLY: the checker rejects altered VC-SDX-K1 vectors', () => {
  const cases = [
    ['k1key-commitment-key', entry => { entry.expected.ciphertext = flip(entry.expected.ciphertext) }],
    ['k1key-root-public-key', entry => { entry.expected.ciphertext = caseById(vectors, 'k1key-second-account-root').expected.ciphertext }],
    ['k1peer-handoff-lock', entry => { entry.brc100.publicKey = flip(entry.brc100.publicKey) }],
    ['k1peer-handoff-lock', entry => { entry.brc100.args.counterparty = 'self' }],
    ['k1key-handoff-recipient-side', entry => { delete entry.brc100.args.forSelf }],
    ['k1key-session', entry => { entry.intermediate.hmac = flip(entry.intermediate.hmac) }],
    ['k1key-actor-persistent-0', entry => { entry.wallet = 'account' }],
    ['k1sign-normalised', entry => {
      const { r, s } = derDecode(fromHex(entry.expected.ciphertext))
      entry.expected.ciphertext = derEncode(r, SECP256K1.n - s).toString('hex')
    }],
    ['k1sign-unchanged', entry => { entry.intermediate.normalised = true }],
    ['k1sign-commitment-spend', entry => { entry.transaction.preimage = flip(entry.transaction.preimage) }],
    ['k1sign-commitment-spend', entry => { entry.transaction.sighashType = 0x42 }],
    ['k1sign-commitment-spend', entry => { entry.request.args.plaintext = flip(entry.request.args.plaintext) }],
    ['k1sign-handoff-spend', entry => { entry.brc100.signature = caseById(vectors, 'k1sign-commitment-spend').expected.ciphertext }],
    ['k1sign-second-account-epoch-0', entry => { entry.intermediate.publicKey = caseById(vectors, 'k1key-second-account-commitment').expected.ciphertext }],
    ['k1key-second-account-epoch-0', entry => { entry.expected.ciphertext = caseById(vectors, 'k1key-second-account-root').expected.ciphertext }],
    ['k1-unknown-epoch', entry => { entry.expected.error = 'unknown-account' }],
    ['k1-epoch-with-session-role', entry => { entry.expected.error = 'session-not-selected' }],
    ['k1-point-x-equals-p', entry => { entry.expected.error = 'point-not-on-curve' }],
    ['k1-point-prefix-04-33-bytes', entry => { entry.curve = 'P-256' }],
    ['offset-range-secp256k1', entry => { entry.values[0].expected = 'accept' }],
    ['offset-range-secp256k1', entry => { entry.values = entry.values.filter(value => value.expected === 'accept') }],
    ['k1key-namespace-rotation', entry => { entry.expected.error = 'path-not-granted' }],
    ['k1key-purpose-unregistered', entry => { entry.expected.error = 'key-path-grammar' }],
    ['k1key-path-record-keyword', entry => { entry.expected.error = 'path-not-granted' }],
    ['k1sign-hash-31-bytes', entry => { entry.expected.error = 'member-type' }],
    ['k1sign-encryption-namespace', entry => { entry.expected.error = 'path-not-granted' }],
    // A missing grant is found before anything the wallet holds is read: the refusal is no-grant
    // whether or not the wallet holds the account (an altered label for either case is caught).
    ['k1-no-grant-from-sign', entry => { entry.expected.error = 'unknown-account' }],
    ['k1-no-grant-unheld-account', entry => { entry.expected.error = 'unknown-account' }],
    ['decrypt-with-k1sign', entry => { entry.request.method = 'encrypt'; entry.request.args.plaintext = entry.request.args.ciphertext; delete entry.request.args.ciphertext }]
  ]
  for (const [id, change] of cases) assert.ok(failedIds(mutate(id, change)).includes(id), id)
  assert.deepEqual(failedIds(mutate('k1key-root-public-key', (_, doc) => { doc.claim = 'CONFORMANT' })), ['(document)'])
  assert.deepEqual(failedIds(mutate('k1key-root-public-key', (_, doc) => { doc.wallets.entries.recipient.accounts[0].epochs[0].K = doc.wallets.entries.account.accounts[0].epochs[0].K })), ['(document)'])
  assert.deepEqual(failedIds(mutate('k1key-root-public-key', (_, doc) => { doc.wallets.profile.namespaces.pop() })), ['(document)'])
})

test('LAB_SELF_TEST_ONLY: secp256k1 RFC 6979 reproduces a published known answer and `k1sign` returns low-S DER', () => {
  // Private key 1, hash SHA-256("Satoshi Nakamoto"): the secp256k1 RFC 6979 known answer
  // that bitcoinjs-lib and python-ecdsa publish.
  const hash = createHash('sha256').update('Satoshi Nakamoto').digest()
  const { r, s, k } = signDeterministic(1n, hash, SECP256K1)
  assert.equal(k.toString(16), '8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15')
  assert.equal(r.toString(16), '934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8')
  assert.equal(lowS(s, SECP256K1).toString(16), '2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5')
  const der = k1Sign(1n, hash)
  assert.deepEqual(derDecode(der), { r, s: lowS(s, SECP256K1) })
  const G = encodePoint(SECP256K1, mulBase(SECP256K1, 1n))
  assert.ok(ecdsaVerify(SECP256K1, G, hash, r, s) && ecdsaVerify(SECP256K1, G, hash, r, SECP256K1.n - s), 'verifiers accept either S')
  assert.equal(ecdsaVerify(SECP256K1, G, createHash('sha256').update(hash).digest(), r, s), false)
  for (const bad of ['3006020101020101' + '00', '300602010002010101', '3007020200010201010', '30060201ff020101', '300702020001020101']) {
    assert.throws(() => derDecode(Buffer.from(bad.length % 2 ? bad + '0' : bad, 'hex')), error => error.code === 'signature-encoding', bad)
  }
})

test('LAB_SELF_TEST_ONLY: k1key and k1peer equal BRC-42 as stock BRC-100 wallets compute it', () => {
  const account = walletFor('account'), recipient = walletFor('recipient')
  const root = account.accounts.get(accountTag(accountId)).epochs.get(0n)
  const other = recipient.accounts.get(accountTag(vectors.profile.identifiers.recipientAccountId)).epochs.get(0n)
  for (let i = 0; i < 4; i++) {
    const keyPath = `account/${accountId}/runtime/${vectors.profile.identifiers.runtimeId}/action/${randomBytes(8).toString('hex')}`
    const own = account.call('encrypt', { protocolID: [2, name('k1key', 'write')], keyID: '1', plaintext: encodeInput({ path: `2-sdx sign-${keyPath}` }) }).ciphertext
    assert.equal(own.toString('hex'), deriveChildPublicKey({ rootPrivateKey: root.secp256k1Seed, protocolID: [2, 'sdx sign'], keyID: keyPath, counterparty: 'self', forSelf: true }).toString('hex'))
    const handoff = `account/${accountId}/runtime/${vectors.profile.identifiers.runtimeId}/action/${vectors.profile.identifiers.recordId}/handoff/${randomBytes(16).toString('hex')}`
    const lock = account.call('encrypt', { protocolID: [2, name('k1peer', 'write')], keyID: '1', plaintext: encodeInput({ path: `2-sdx handoff-${handoff}`, peer: other.K }) }).ciphertext
    assert.equal(lock.toString('hex'), deriveChildPublicKey({ rootPrivateKey: root.secp256k1Seed, protocolID: [2, 'sdx handoff'], keyID: handoff, counterparty: other.K.toString('hex') }).toString('hex'))
    const spend = recipient.call('encrypt', { protocolID: [2, name('k1key', 'write', vectors.profile.identifiers.recipientAccountId)], keyID: '1', plaintext: encodeInput({ path: `2-sdx handoff-${handoff}`, peer: root.K }) }).ciphertext
    assert.equal(spend.toString('hex'), lock.toString('hex'), 'counterparty symmetry')
  }
})

test('LAB_SELF_TEST_ONLY: secp256k1 peers are validated before any parser, and k1 operations are separate from P-256 ones', () => {
  const account = walletFor('account')
  const path = caseById(vectors, 'k1peer-handoff-lock').request.input.path
  const call = (operation, input, options) => account.call('encrypt', { protocolID: [2, name(operation, 'write')], keyID: '1', plaintext: encodeInput(input) }, options)
  const at = (prefix, x) => Buffer.concat([Buffer.from([prefix]), int32(x)])
  for (const [bytes, code] of [[at(2, SECP256K1.p), 'point-x-range'], [at(3, SECP256K1.p + 1n), 'point-x-range'], [at(4, 1n), 'point-prefix'], [Buffer.alloc(32, 1), 'point-length']]) {
    assert.throws(() => decodePoint(SECP256K1, bytes), error => error instanceof EcError && error.code === code, code)
    assert.throws(() => call('k1peer', { path, peer: bytes }), error => error.code === code, `k1peer ${code}`)
  }
  // A P-256 operation on a path in `sdx handoff`, a secp256k1-only namespace, is refused.
  assert.throws(() => account.call('encrypt', { protocolID: [2, name('key', 'write')], keyID: '1', plaintext: encodeInput({ path }) }), error => error.code === 'namespace-curve')
  // A sign grant does not cover k1sign: the account wallet has no `k1sign write` grant for the second account's other paths.
  assert.throws(() => call('k1sign', { path: caseById(vectors, 'k1sign-commitment-spend').request.input.path.replace(accountId, `${accountId}X`), hash: Buffer.alloc(32, 7) }), error => error.code === 'path-not-granted')
  // Injected offsets: h = 1 is used as given; h = n is refused.
  const commitment = caseById(vectors, 'k1key-commitment-key').request.input.path
  const root = account.accounts.get(accountTag(accountId)).epochs.get(0n)
  assert.equal(call('k1key', { path: commitment }, { injectHmac: int32(1n) }).ciphertext.toString('hex'), encodePoint(SECP256K1, mulBase(SECP256K1, mod(root.k + 1n, SECP256K1.n))).toString('hex'))
  assert.throws(() => call('k1key', { path: commitment }, { injectHmac: int32(SECP256K1.n) }), error => error.code === 'scalar-rejected' && error.message.endsWith('secp256k1'))
  // ep selects the epoch on secp256k1 too.
  const second = account.accounts.get(accountTag(secondAccountId))
  const k1 = (input) => account.call('encrypt', { protocolID: [2, name('k1key', 'write', secondAccountId)], keyID: '1', plaintext: encodeInput(input) }).ciphertext.toString('hex')
  assert.equal(k1({}), second.epochs.get(1n).K.toString('hex'))
  assert.equal(k1({ ep: 0n }), second.epochs.get(0n).K.toString('hex'))
  assert.equal(toInt(fromHex(k1({}).slice(2))) === toInt(fromHex(k1({ ep: 0n }).slice(2))), false)
})
