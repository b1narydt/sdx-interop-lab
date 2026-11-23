import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { randomBytes } from 'node:crypto'
import {
  P256, accountTag, checkJweShape, checkKeyPath, checkOffset, checkVcP256, createWallet, decodeInput, encodeInput, es256Sign, es256Verify, fromHex,
  inputFromJson, jweDecrypt, ownChild, seedInRange, signDeterministic, splitIkm
} from '../src/sdx/p256.mjs'
import { EcError, decodePoint, ecdhPoint, encodePoint, int32, mod, mulBase, toInt } from '../src/sdx/ec-p256.mjs'
import { N as K1_N, offsetScalar } from '../src/sdx/brc42.mjs'

const vectors = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/vc-p256/vectors.json', import.meta.url)))
const labels = vectors.testKeys.labels
const caseById = (doc, id) => doc.cases.find(entry => entry.id === id)
const mutate = (id, change) => {
  const copy = structuredClone(vectors)
  change(caseById(copy, id), copy)
  return checkVcP256(copy)
}
const failedIds = report => report.failures.map(failure => failure.id)
const walletFor = (name, change = entry => entry) => createWallet({ entry: change(structuredClone(vectors.wallets.entries[name])), profile: vectors.wallets.profile, derivation: vectors.wallets.walletRootDerivation })
const { accountId, secondAccountId } = vectors.profile.identifiers
const name = (operation, role, acct = accountId) => `p sdx ${operation} ${role} ${accountTag(acct)}`

test('LAB_SELF_TEST_ONLY: VC-P256 vectors pass the independent node:crypto checker', () => {
  const report = checkVcP256(vectors)
  assert.deepEqual(report.failures, [])
  assert.equal(report.cases, 177)
  assert.equal(report.passed, 165)
  assert.equal(report.behavioural, 12)
  assert.equal(vectors.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(vectors.generator.grind.seed.smallest && vectors.generator.grind.path.smallest, true)
})

test('LAB_SELF_TEST_ONLY: the checker rejects altered vectors', () => {
  const flip = text => text.slice(0, -1) + (text.at(-1) === '0' ? '1' : '0')
  const cases = [
    ['key-record-signing-self', entry => { entry.expected.ciphertext = flip(entry.expected.ciphertext) }],
    ['key-root-public-key', entry => { entry.expected.ciphertext = caseById(vectors, 'key-record-signing-self').expected.ciphertext }],
    ['key-recipient-record-kid', entry => { entry.intermediate.hmac = flip(entry.intermediate.hmac) }],
    // The RFC 6979 form of a normalised signature is a valid ES256 signature, but not the module's result.
    ['sign-record-normalised', entry => { entry.expected.ciphertext = entry.intermediate.rfc6979 }],
    ['sign-record-unchanged', entry => { entry.intermediate.normalised = true }],
    ['es256-rfc6979-a25-sample', entry => { entry.expected.signature = entry.expected.rfc6979 }],
    ['es256-rfc6979-a25-sample', entry => { entry.expected.k = flip(entry.expected.k) }],
    ['decrypt-outer-recipient-entry', entry => { entry.expected.plaintext = flip(entry.expected.plaintext) }],
    ['decrypt-outer-recipient-entry', entry => { entry.request.args.ciphertext = flip(entry.request.args.ciphertext) }],
    ['decrypt-outer-recipient-entry', entry => { entry.intermediate.cek = flip(entry.intermediate.cek) }],
    ['decrypt-outer-self', entry => { entry.intermediate.kek = flip(entry.intermediate.kek) }],
    ['decrypt-field-recipient-entry', entry => { entry.request = caseById(vectors, 'decrypt-wrong-path').request }],
    ['decrypt-wrong-path', entry => { entry.expected = caseById(vectors, 'decrypt-field-recipient-entry').expected }],
    ['decrypt-signing-namespace', entry => { entry.expected.error = 'path-not-granted' }],
    ['decrypt-epk-y-mismatch', entry => { entry.expected.error = 'jwe-shape' }],
    ['decrypt-alg-ecdh-es', entry => { entry.expected.error = 'decrypt-failed' }],
    ['key-namespace-rotation', entry => { entry.expected.error = 'path-not-granted' }],
    ['key-purpose-unregistered', entry => { entry.expected.error = 'key-path-grammar' }],
    ['key-path-record-keyword', entry => { entry.expected.error = 'path-not-granted' }],
    ['key-path-actor-under-account-role', entry => { entry.expected.error = 'path-not-granted' }],
    ['key-path-1034-bytes', entry => { entry.expected.error = 'key-path-grammar' }],
    ['key-path-1033-bytes', entry => { entry.expected.ciphertext = flip(entry.expected.ciphertext) }],
    ['sign-actor-persistent-0', entry => { entry.expected.ciphertext = entry.intermediate.rfc6979 }],
    ['key-offset-rejected', entry => { entry.expected = { ciphertext: '02' + '00'.repeat(32) } }],
    ['key-path-nfd', entry => { entry.expected.ciphertext = caseById(vectors, 'key-path-nfc').expected.ciphertext }],
    ['key-actor-persistent-0', entry => { entry.expected.ciphertext = caseById(vectors, 'key-session-p256').expected.ciphertext }],
    ['key-session-p256', entry => { entry.wallet = 'account' }],
    ['point-x-equals-p', entry => { entry.expected.error = 'point-not-on-curve' }],
    ['path-outside-grant-account', entry => { entry.expected.error = 'no-grant' }],
    ['privileged-request', entry => { delete entry.request.args.privileged }],
    ['split-account', entry => { entry.expected.p256Seed = flip(entry.expected.p256Seed) }],
    ['wallet-root-epoch-0', entry => { entry.expected.ikm = flip(entry.expected.ikm) }],
    ['wallet-root-epoch-1', entry => { entry.input.salt = 'p p256 v1' }],
    ['wallet-root-new-account', entry => { entry.input.keyID = entry.input.keyID.replace(' 0', ' 1') }],
    ['offset-range-p256', entry => { entry.values[3].expected = 'accept' }],
    ['encrypt-with-decrypt', entry => { entry.request.method = 'decrypt'; entry.request.args.ciphertext = entry.request.args.plaintext; delete entry.request.args.plaintext }],
    ['removed-operation-link', entry => { entry.request.args.protocolID[1] = entry.request.args.protocolID[1].replace('link', 'key') }],
    // Root selection, epochs and open.
    ['open-current-epoch', entry => { entry.expected.ciphertext = caseById(vectors, 'open-earlier-epoch').expected.ciphertext }],
    ['open-imported-account', entry => { entry.expected.ciphertext = entry.expected.ciphertext.slice(0, 66) }],
    ['open-creates-account', entry => { delete entry.prompt }],
    ['open-creates-epoch', entry => { entry.matches = 'wallet-root-epoch-1' }],
    ['key-second-account-epoch-0', entry => { entry.expected.ciphertext = caseById(vectors, 'key-second-account-root').expected.ciphertext }],
    ['key-second-account-epoch-1', entry => { entry.request.input = { ep: 0 }; entry.request.args.plaintext = encodeInput({ ep: 0n }).toString('hex') }],
    ['sign-second-account-epoch-0', entry => { entry.intermediate.childPrivate = caseById(vectors, 'key-second-account-record').intermediate.childPrivate }],
    ['unknown-epoch', entry => { entry.expected.error = 'unknown-account' }],
    ['unknown-account', entry => { entry.expected.error = 'no-grant' }],
    // Without a grant the refusal is no-grant, whether or not the wallet holds the account or epoch.
    ['no-grant-unheld-account', entry => { entry.expected.error = 'unknown-account' }],
    ['no-grant-unheld-epoch', entry => { entry.expected.error = 'unknown-epoch' }],
    ['epoch-with-actor-role', entry => { delete entry.request.input.ep; entry.request.args.plaintext = encodeInput(inputFromJson(entry.request.input)).toString('hex') }],
    ['session-key-without-path', entry => { entry.expected.error = 'no-grant' }],
    ['sign-encryption-namespace', entry => { entry.expected.error = 'path-not-granted' }],
    ['key-namespace-wrong-curve', entry => { entry.expected.error = 'namespace-unregistered' }],
    ['open-tag-mismatch', entry => { entry.expected.error = 'unknown-account' }],
    ['logical-previous-form', entry => { entry.request.args.protocolID[1] = name('key', 'write') }],
    ['ep-negative', entry => { entry.expected.error = 'input-encoding' }],
    ['cbor-non-shortest-integer', entry => { entry.request.args.plaintext = encodeInput({ ep: 1n }).toString('hex') }]
  ]
  // The altered case always fails; cases that reference it (sameAs, differsFrom, matches) may fail with it.
  for (const [id, change] of cases) assert.ok(failedIds(mutate(id, change)).includes(id), id)
  const documentLevel = [
    doc => { doc.claim = 'CONFORMANT' },
    doc => { doc.profile.accountTags[accountId] = '00'.repeat(16) },
    doc => { doc.wallets.entries.account.grants[2].prefixes = ['2-sdx sign-account/3MNQpxFAsp'] },
    doc => { doc.wallets.entries.account.accounts[1].current = 0 },
    doc => { doc.wallets.entries.account.accounts[1].epochs[0].R = doc.wallets.entries.account.accounts[1].epochs[1].R },
    doc => { doc.wallets.entries.account.accounts[0].tag = accountTag(secondAccountId) },
    doc => { doc.wallets.walletRootDerivation.salt = 'p p256 v1' },
    doc => { doc.wallets.entries.actor.sessions[Object.keys(doc.wallets.entries.actor.sessions)[0]].ikm = doc.wallets.entries.actor.actor.ikm },
    doc => { doc.wallets.profile.purposes = [...doc.wallets.profile.purposes, 'photo'] },
    doc => { doc.profile.keywords = { ...doc.profile.keywords, action: 'record' } },
    doc => { doc.profile.formatIdentifier = 'sdx:record:v1' }
  ]
  for (const change of documentLevel) assert.deepEqual(failedIds(mutate('split-account', (_, doc) => change(doc))), ['(document)'])
})

test('LAB_SELF_TEST_ONLY: RFC 6979 A.2.5 nonces are reproduced and `sign` returns the low-S form', () => {
  const d = 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721n
  const publicKey = encodePoint(P256, mulBase(P256, d))
  const message = Buffer.from('sample')
  const { r, s, k } = signDeterministic(d, Buffer.from('af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf', 'hex'))
  assert.equal(k.toString(16), 'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60')
  assert.equal(int32(r).toString('hex') + int32(s).toString('hex'), 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8')
  assert.ok(s > P256.n / 2n, 'the RFC sample signature is high-S')
  const signature = es256Sign(d, message)
  assert.equal(signature.toString('hex'), int32(r).toString('hex') + int32(P256.n - s).toString('hex'))
  assert.ok(es256Verify(publicKey, message, signature))
  assert.ok(es256Verify(publicKey, message, Buffer.concat([int32(r), int32(s)])), 'verifiers accept either S')
  const test2 = es256Sign(d, Buffer.from('test'))
  assert.equal(test2.toString('hex'), 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083', 'an already low s is unchanged')
  assert.equal(es256Verify(publicKey, Buffer.from('samplf'), signature), false)
  assert.equal(es256Verify(publicKey, message, signature.subarray(1)), false)
  assert.equal(es256Verify(encodePoint(P256, mulBase(P256, d + 1n)), message, signature), false)
})

test('LAB_SELF_TEST_ONLY: point validation runs before any parser and ECDH recovers the full point', () => {
  const valid = fromHex(vectors.testKeys.roots.recipient.p256PublicKey)
  assert.ok(decodePoint(P256, valid))
  const at = (prefix, x) => Buffer.concat([Buffer.from([prefix]), int32(x)])
  for (const [bytes, code] of [
    [at(2, (1n << 256n) - 1n), 'point-x-range'], [at(2, P256.p), 'point-x-range'], [at(3, P256.p + 1n), 'point-x-range'],
    [at(2, 1n), 'point-not-on-curve'], [at(4, 1n), 'point-prefix'], [Buffer.concat([valid, Buffer.from([0])]), 'point-length'],
    [Buffer.from([0]), 'point-length'], [Buffer.alloc(0), 'point-length']
  ]) assert.throws(() => decodePoint(P256, bytes), error => error instanceof EcError && error.code === code, code)
  for (let i = 0; i < 8; i++) {
    const k = mod(toInt(randomBytes(32)), P256.n - 1n) + 1n, q = mod(toInt(randomBytes(32)), P256.n - 1n) + 1n
    const Q = encodePoint(P256, mulBase(P256, q))
    assert.equal(encodePoint(P256, ecdhPoint(P256, k, Q)).toString('hex'), encodePoint(P256, mulBase(P256, mod(k * q, P256.n))).toString('hex'))
  }
  assert.equal(encodePoint(P256, ecdhPoint(P256, P256.n - 1n, valid)).toString('hex'), encodePoint(P256, { ...decodePoint(P256, valid), y: P256.p - decodePoint(P256, valid).y }).toString('hex'))
})

test('LAB_SELF_TEST_ONLY: injected seeds and offsets are rejected, never clamped or reduced', () => {
  for (const value of [0n, P256.n, P256.n + 1n, (1n << 256n) - 1n]) assert.throws(() => checkOffset(int32(value)), error => error.code === 'scalar-rejected')
  for (const value of [1n, P256.n - 1n]) assert.equal(checkOffset(int32(value)), value)
  for (const value of [0n, K1_N, K1_N + 1n]) assert.throws(() => offsetScalar(int32(value)), error => error.code === 'ERR_DERIVATION_SCALAR')
  for (const [curve, n] of [['p256', P256.n], ['secp256k1', K1_N]]) {
    assert.deepEqual([0n, 1n, n - 1n, n].map(value => seedInRange(curve, int32(value))), [false, true, true, false])
  }
  assert.throws(() => splitIkm(fromHex(vectors.testKeys.roots.unusable.ikm), labels), error => error.code === 'ikm-unusable' && error.message.endsWith('P-256'))
  assert.throws(() => splitIkm(Buffer.alloc(32), labels), error => error.code === 'ikm-length')
  assert.throws(() => splitIkm(Buffer.alloc(64), { secp256k1: 'sdx-p256', p256: 'sdx-p256' }), error => error.code === 'profile-labels')
})

test('LAB_SELF_TEST_ONLY: module inputs are strict deterministic CBOR, with unsigned integers for `ep`', () => {
  const good = encodeInput({ path: 'abc', peer: Buffer.from([1, 2]) })
  assert.equal(good.toString('hex'), 'a2647061746863616263647065657242' + '0102')
  assert.deepEqual({ ...decodeInput(good) }, { path: 'abc', peer: Buffer.from([1, 2]) })
  assert.equal(encodeInput({ ep: 1n, path: 'abc' }).toString('hex'), 'a262657001647061746863616263')
  assert.deepEqual({ ...decodeInput(encodeInput({ ep: 300n })) }, { ep: 300n })
  assert.deepEqual({ ...decodeInput(encodeInput({ ep: -1n })) }, { ep: -1n })
  assert.deepEqual({ ...decodeInput(encodeInput({ ep: 1n << 40n })) }, { ep: 1n << 40n })
  const pathEntry = encodeInput({ path: 'abc' }).subarray(1), peerEntry = encodeInput({ peer: Buffer.from([1, 2]) }).subarray(1)
  const encodings = {
    truncated: Buffer.from('a1', 'hex'),
    unsorted: Buffer.concat([Buffer.from('a2', 'hex'), peerEntry, pathEntry]),
    duplicate: Buffer.concat([Buffer.from('a2', 'hex'), pathEntry, pathEntry]),
    nonShortestLength: Buffer.concat([Buffer.from('a17804', 'hex'), Buffer.from('path'), Buffer.from('63616263', 'hex')]),
    nonShortestInteger: Buffer.from('a16265701801', 'hex'),
    nonShortestInteger8: Buffer.from('a162657019' + '0001', 'hex'),
    trailing: Buffer.concat([good, Buffer.from([0])]),
    indefiniteMap: Buffer.concat([Buffer.from('bf', 'hex'), pathEntry, Buffer.from('ff', 'hex')]),
    notMap: Buffer.concat([Buffer.from('81', 'hex'), Buffer.from('63616263', 'hex')]),
    floatValue: Buffer.concat([Buffer.from('a1', 'hex'), pathEntry.subarray(0, 5), Buffer.from('f93c00', 'hex')]),
    badUtf8: Buffer.concat([Buffer.from('a1', 'hex'), pathEntry.subarray(0, 5), Buffer.from('62c328', 'hex')])
  }
  for (const [label, bytes] of Object.entries(encodings)) {
    assert.throws(() => decodeInput(bytes), error => error.code === 'input-encoding', label)
  }
})

test('LAB_SELF_TEST_ONLY: the logical protocol ID selects the account and epoch; grants scope paths, operations and accounts', () => {
  const account = walletFor('account')
  const path = caseById(vectors, 'key-record-signing-self').request.input.path
  const call = (protocolName, input, extra = {}) => account.call('encrypt', { protocolID: [2, protocolName], keyID: '1', plaintext: encodeInput(input), ...extra })
  const listed = vectors.wallets.entries.account.accounts
  assert.equal(call(name('key', 'write'), { path }).ciphertext.toString('hex'), caseById(vectors, 'key-record-signing-self').expected.ciphertext)
  assert.equal(call(name('key', 'write'), {}).ciphertext.toString('hex'), listed[0].epochs[0].R)
  assert.equal(call(name('key', 'write', secondAccountId), {}).ciphertext.toString('hex'), listed[1].epochs[1].R)
  assert.equal(call(name('key', 'write', secondAccountId), { ep: 0n }).ciphertext.toString('hex'), listed[1].epochs[0].R)
  assert.equal(call(name('open', 'root', secondAccountId), { acct: secondAccountId }).ciphertext.toString('hex'), listed[1].epochs[1].R + listed[1].epochs[1].K)
  assert.throws(() => call(name('key', 'write', secondAccountId), { ep: 2n }), error => error.code === 'unknown-epoch')
  assert.throws(() => call(name('key', 'write'), { path: path.replace('3MNQpxFAsp', '3MNQpxFAsq') }), error => error.code === 'path-not-granted')
  assert.throws(() => call(name('key', 'write'), { path }, { privileged: true, privilegedReason: 'LAB_SELF_TEST_ONLY' }), error => error.code === 'privileged-not-supported')
  assert.throws(() => call(name('sign', 'write', secondAccountId), { path, msg: Buffer.from('x') }), error => error.code === 'path-not-granted', 'the second account\'s grant does not cover the first account\'s paths')
  assert.throws(() => call(`p p256 key sdx write ${accountTag(accountId)}`, { path }), error => error.code === 'not-sdx-request')
  const ungranted = walletFor('account', entry => ({ ...entry, grants: [] }))
  assert.throws(() => ungranted.call('encrypt', { protocolID: [2, name('key', 'write')], keyID: '1', plaintext: encodeInput({ path }) }), error => error.code === 'no-grant')
  assert.equal(ungranted.call('encrypt', { protocolID: [2, name('key', 'write')], keyID: '1', plaintext: encodeInput({ path }) }, { approve: true }).ciphertext.toString('hex'), caseById(vectors, 'key-record-signing-self').expected.ciphertext, 'an approved prompt stands in for a grant')
  // A wallet without a wallet root cannot create accounts.
  const recipient = walletFor('recipient')
  assert.throws(() => recipient.call('encrypt', { protocolID: [2, name('open', 'root')], keyID: '1', plaintext: encodeInput({ acct: accountId }) }, { approve: true }), error => error.code === 'cannot-create')
})

test('LAB_SELF_TEST_ONLY: a session root is drawn on first use and then kept', () => {
  const actor = walletFor('actor')
  const path = caseById(vectors, 'key-session-p256').request.input.path.replace(vectors.profile.identifiers.sessionId, '0'.repeat(32))
  const call = () => actor.call('encrypt', { protocolID: [2, name('key', 'session')], keyID: '1', plaintext: encodeInput({ path }) }).ciphertext.toString('hex')
  const first = call()
  assert.equal(call(), first)
  assert.notEqual(walletFor('actor').call('encrypt', { protocolID: [2, name('key', 'session')], keyID: '1', plaintext: encodeInput({ path }) }).ciphertext.toString('hex'), first, 'another wallet draws another root')
})

test('LAB_SELF_TEST_ONLY: decrypt opens only with the one candidate key, and results never carry secrets', () => {
  const roots = vectors.testKeys.roots
  const account = walletFor('account')
  const outer = caseById(vectors, 'decrypt-outer-self')
  const input = inputFromJson(outer.request.input)
  const rootScalar = toInt(fromHex(roots.account.p256Seed)), rootPublic = fromHex(roots.account.p256PublicKey)
  const child = ownChild(rootScalar, rootPublic, input.path)
  assert.equal(jweDecrypt(child.childPrivate, input.jwe).plaintext.toString('hex'), outer.expected.plaintext)
  assert.throws(() => jweDecrypt(child.childPrivate + 1n, input.jwe), error => error.code === 'decrypt-failed')
  // The shape is checked before any key: alg, the two headers, and the ephemeral key.
  assert.throws(() => checkJweShape({ ...input.jwe, header: { ...input.jwe.header, alg: 'A256KW' } }), error => error.code === 'jwe-shape')
  assert.throws(() => checkJweShape({ ...input.jwe, recipients: [] }), error => error.code === 'jwe-shape')
  assert.throws(() => checkJweShape({ ...input.jwe, header: { ...input.jwe.header, crit: ['b64'] } }), error => error.code === 'jwe-shape')
  const prot = JSON.parse(Buffer.from(input.jwe.protected, 'base64url'))
  const withEpk = epk => ({ ...input.jwe, protected: Buffer.from(JSON.stringify({ ...prot, epk })).toString('base64url') })
  assert.throws(() => checkJweShape(withEpk({ ...prot.epk, d: prot.epk.x })), error => error.code === 'jwe-shape')
  assert.throws(() => checkJweShape(withEpk({ ...prot.epk, x: Buffer.alloc(32, 255).toString('base64url') })), error => error.code === 'point-x-range')
  const path = caseById(vectors, 'key-record-signing-self').request.input.path
  const secrets = [roots.account.ikm, roots.account.p256Seed, roots.account.secp256k1Seed, int32(ownChild(rootScalar, rootPublic, path).childPrivate).toString('hex'), int32(child.childPrivate).toString('hex'), outer.intermediate.cek]
  const results = [
    account.call('encrypt', { protocolID: [2, name('key', 'write')], keyID: '1', plaintext: encodeInput({}) }).ciphertext,
    account.call('encrypt', { protocolID: [2, name('key', 'write')], keyID: '1', plaintext: encodeInput({ path }) }).ciphertext,
    account.call('encrypt', { protocolID: [2, name('sign', 'write')], keyID: '1', plaintext: encodeInput({ path, msg: Buffer.from('x') }) }).ciphertext,
    account.call('encrypt', { protocolID: [2, name('open', 'root')], keyID: '1', plaintext: encodeInput({ acct: accountId }) }).ciphertext,
    account.call('decrypt', { protocolID: [2, name('decrypt', 'read')], keyID: '1', ciphertext: fromHex(outer.request.args.ciphertext) }).plaintext
  ]
  assert.deepEqual(results.slice(0, 4).map(result => result.length), [33, 33, 64, 66])
  assert.ok(toInt(results[2].subarray(32)) <= P256.n / 2n, 'sign returns low S')
  for (const result of results) for (const secret of secrets) assert.equal(result.toString('hex').includes(secret.slice(0, 16)), false)
})

test('LAB_SELF_TEST_ONLY: key paths follow KEYS §1.6.1 with the profile\'s keywords and closed purpose set', () => {
  const profile = vectors.wallets.profile
  const scope = `account/${accountId}/runtime/${vectors.profile.identifiers.runtimeId}`
  const aid = vectors.profile.identifiers.recordId
  for (const ok of [`account/${accountId}`, scope, `${scope}/action/${aid}`, `${scope}/action/${aid}/field/x`, `${scope}/action/${aid}/handoff/ab`, `${scope}/action/${aid}/topup/0`, `${scope}/session/${'ab'.repeat(16)}`]) {
    assert.doesNotThrow(() => checkKeyPath(ok, 'write', 'signing', profile), ok)
  }
  assert.throws(() => checkKeyPath(`${scope}/action/${aid}/photo/x`, 'write', 'signing', profile), error => error.code === 'purpose-unregistered')
  for (const bad of [`${scope}/record/${aid}`, `${scope}/action`, `${scope}//x`, `${scope}/action/${aid}/field`, `${scope}/delegation/${'00'.repeat(16)}/actor/02`, 'actor/0']) {
    assert.throws(() => checkKeyPath(bad, 'write', 'signing', profile), error => error.code === 'key-path-grammar', bad)
  }
  assert.doesNotThrow(() => checkKeyPath('actor/7', 'actor', 'delegation', profile))
  for (const [keyPath, ns] of [['actor/07', 'delegation'], ['actor/0', 'signing'], [`${scope}/action/${aid}`, 'delegation']]) {
    assert.throws(() => checkKeyPath(keyPath, 'actor', ns, profile), error => error.code === 'key-path-grammar', keyPath)
  }
  assert.doesNotThrow(() => checkKeyPath(`${scope}/action/`.padEnd(1033, '0'), 'write', 'signing', profile))
  assert.throws(() => checkKeyPath(`${scope}/action/`.padEnd(1034, '0'), 'write', 'signing', profile), error => error.code === 'key-path-length')
})

test('LAB_SELF_TEST_ONLY: both module suites use the published laboratory deployment profile, byte for byte (KEYS §1.3.1)', () => {
  const lab = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/deployment-profile.json', import.meta.url)))
  const k1 = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/vc-sdx-k1/vectors.json', import.meta.url)))
  const { namespaces, curveLabels, keyPath, credentialType } = lab.derivation
  const roles = { encryption: 'encryption', signing: 'signing', delegation: 'delegation', 'transport authentication': 'transportAuthentication', rotation: 'rotation', handoff: 'handoff' }
  const keywords = { account: keyPath.keywords.level1, runtime: keyPath.keywords.level2, action: keyPath.keywords.level3, session: keyPath.keywords.level3Session, delegation: keyPath.keywords.level3Delegation, actor: keyPath.keywords.delegationActor }
  for (const doc of [vectors, k1]) {
    assert.equal(doc.profile.file, 'fixtures/sdx/v1/deployment-profile.json')
    assert.equal(doc.profile.formatIdentifier, lab.formatIdentifier.value)
    assert.equal(doc.profile.credentialType, credentialType.value)
    assert.deepEqual(doc.profile.labels, { secp256k1: curveLabels.secp256k1, p256: curveLabels.p256 })
    assert.deepEqual(Object.values(doc.profile.namespaces).sort(), Object.values(namespaces).filter(value => typeof value === 'string' && value !== namespaces.basis).sort())
    for (const row of doc.wallets.profile.namespaces) assert.equal(row.namespace, namespaces[roles[row.role]], row.role)
    assert.deepEqual(doc.wallets.profile.keywords, keywords)
    assert.deepEqual(doc.wallets.profile.purposes, keyPath.purposes.map(entry => entry.purpose))
    assert.equal(keywords.action, 'action', 'one level-3 keyword on both curves (reading R1)')
  }
})

test('LAB_SELF_TEST_ONLY: every local citation of the module suites resolves to its file and clause', () => {
  const k1 = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/vc-sdx-k1/vectors.json', import.meta.url)))
  for (const doc of [vectors, k1]) {
    const citations = [...doc.citations, ...doc.cases.filter(entry => entry.citation).map(entry => entry.citation)]
    for (const citation of citations) {
      if (citation.repository || citation.path.startsWith('https://')) continue
      const text = fs.readFileSync(new URL(`../${citation.path}`, import.meta.url), 'utf8')
      for (const clause of citation.clause.replace(/^requirements /, '').split(', ')) {
        assert.ok(text.includes(clause.replace(/^§/, '')), `${doc.suite} ${citation.path}: ${clause}`)
      }
    }
  }
})
