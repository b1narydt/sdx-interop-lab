#!/usr/bin/env node
// LAB_SELF_TEST_ONLY generator for the VC-P256 and VC-SDX-K1 vector suites of
// the `p sdx` BRC-98 module draft (SDX accounts on both curves).
//
// Libraries: @noble/curves and @noble/hashes (P-256 and secp256k1 arithmetic,
// HKDF, HMAC, RFC 6979 ECDSA), cborg (deterministic CBOR), jose (the
// ECDH-ES+A256KW JWEs that `decrypt` opens) and @bsv/sdk (BRC-42 keys, BRC-100
// getPublicKey and createSignature, and the transaction of the commitment-spend
// case). The checkers (src/sdx/p256.mjs, src/sdx/k1.mjs, src/sdx/ec-p256.mjs
// with src/sdx/brc42.mjs and src/sdx/tx.mjs, and test/sdx_ec.py with
// test/sdx_module.py) import none of them.
//
//   node generate.mjs --write   regenerate the two vectors.json files
//   node generate.mjs --check   regenerate in memory and require identical bytes
//
// Every value is deterministic except the JWEs, which jose makes with a random
// content-encryption key, IV and ephemeral key. They are generated once, frozen
// in frozen.json together with the inputs they were made for, and re-verified
// by decryption on every run.
import fs from 'node:fs'
import path from 'node:path'
import { createDecipheriv } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { p256 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg'
import * as jose from 'jose'
import { BigNumber, ECDSA, Hash, KeyDeriver, LockingScript, PrivateKey, ProtoWallet, Spend, Transaction, TransactionSignature, UnlockingScript } from '@bsv/sdk'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO = path.resolve(HERE, '../../..')
const OUTPUTS = {
  vc: 'fixtures/sdx/v1/vc-p256/vectors.json',
  k1: 'fixtures/sdx/v1/vc-sdx-k1/vectors.json'
}
const FROZEN_FILE = path.join(HERE, 'frozen.json')
const mode = process.argv[2]
if (process.argv.length !== 3 || !['--write', '--check'].includes(mode)) {
  console.error('usage: node generate.mjs --write | --check')
  process.exit(2)
}

const hex = bytes => Buffer.from(bytes).toString('hex')
const unhex = text => Uint8Array.from(Buffer.from(text, 'hex'))
const utf8 = text => new TextEncoder().encode(text)
const toBig = bytes => BigInt('0x' + (hex(bytes) || '0'))
const be32 = value => unhex(value.toString(16).padStart(64, '0'))
const b64u = bytes => Buffer.from(bytes).toString('base64url')
const fail = message => { throw new Error(`generator self-check failed: ${message}`) }
const same = (a, b, what) => { if (hex(a) !== hex(b)) fail(what) }

const N = p256.Point.CURVE().n
const P = p256.Point.CURVE().p
const NK = secp256k1.Point.CURVE().n
const PK = secp256k1.Point.CURVE().p
const G = p256.Point.BASE
const GK = secp256k1.Point.BASE
const point = bytes => p256.Point.fromHex(hex(bytes))
const k1Point = bytes => secp256k1.Point.fromHex(hex(bytes))

// The laboratory deployment profile, published once for every SDX suite (KEYS
// §1.3.1 items 1 to 4, ENV §2.1). Every string that enters a derivation comes
// from it: the labels, namespaces, key-path keywords and purposes are SDX's
// example values, used for the laboratory only, and the format identifier is the
// laboratory's own. The level-3 keyword is `action` on both curves (its reading
// R1). `actor`, the keyword of the delegation variant's actor segment, also names
// the actor's persistent key path `actor/<index>` (module draft, step 1). The
// identifiers are the worked example of KEYS §1.8.1.
const PROFILE_FILE = 'fixtures/sdx/v1/deployment-profile.json'
const LAB_PROFILE = JSON.parse(fs.readFileSync(path.join(REPO, PROFILE_FILE), 'utf8'))
if (LAB_PROFILE.claim !== 'LAB_SELF_TEST_ONLY' || LAB_PROFILE.profile !== LAB_PROFILE.formatIdentifier.value) fail('laboratory deployment profile')
const FORMAT_IDENTIFIER = LAB_PROFILE.formatIdentifier.value
const LABELS = { secp256k1: LAB_PROFILE.derivation.curveLabels.secp256k1, p256: LAB_PROFILE.derivation.curveLabels.p256 }
const NAMESPACES = (ns => ({ encrypt: ns.encryption, sign: ns.signing, delegate: ns.delegation, transportAuth: ns.transportAuthentication, rotation: ns.rotation, handoff: ns.handoff }))(LAB_PROFILE.derivation.namespaces)
const KEYWORDS = (kw => ({ account: kw.level1, runtime: kw.level2, action: kw.level3, session: kw.level3Session, delegation: kw.level3Delegation, actor: kw.delegationActor }))(LAB_PROFILE.derivation.keyPath.keywords)
const PURPOSES = LAB_PROFILE.derivation.keyPath.purposes.map(entry => entry.purpose)
const CREDENTIAL_TYPE = LAB_PROFILE.derivation.credentialType.value
for (const value of [FORMAT_IDENTIFIER, CREDENTIAL_TYPE, ...Object.values(LABELS), ...Object.values(NAMESPACES), ...Object.values(KEYWORDS), ...PURPOSES]) if (typeof value !== 'string' || !value) fail('laboratory deployment profile value')
// KEYS §1.7: the six roles of the example profile and the curves each serves.
const REGISTERED = [
  { role: 'encryption', namespace: NAMESPACES.encrypt, curves: ['secp256k1', 'P-256'] },
  { role: 'signing', namespace: NAMESPACES.sign, curves: ['secp256k1', 'P-256'] },
  { role: 'delegation', namespace: NAMESPACES.delegate, curves: ['secp256k1', 'P-256'] },
  { role: 'transport authentication', namespace: NAMESPACES.transportAuth, curves: ['secp256k1'] },
  { role: 'rotation', namespace: NAMESPACES.rotation, curves: ['secp256k1', 'P-256'] },
  { role: 'handoff', namespace: NAMESPACES.handoff, curves: ['secp256k1'] }
]
const IDS = {
  accountId: '3MNQpxFAsp',
  secondAccountId: '5QkVr9TzWm',
  newAccountId: '7HdWq2KxRb',
  recipientAccountId: '9VxTqR3mLp',
  runtimeId: '8kRt2wVbZq',
  recordId: '01JB8ZK3QN7T4YVX2C9M5RDPWA',
  secondRecordId: '01JB8ZK3QP8V2R5W9X3Y6Z1A4C',
  fieldName: 'photoHash',
  delId: '00112233445566778899aabbccddeeff',
  sessionId: 'ffeeddccbbaa99887766554433221100',
  refIdHex: hex(sha256(utf8('LAB_SELF_TEST_ONLY handoff reference 1')).subarray(0, 16))
}
const A_ID = IDS.accountId, A2_ID = IDS.secondAccountId, NEW_ID = IDS.newAccountId, B_ID = IDS.recipientAccountId
const scopeOf = acct => `${KEYWORDS.account}/${acct}/${KEYWORDS.runtime}/${IDS.runtimeId}`
const SCOPE = scopeOf(A_ID)
const actionOf = (scope, actionId) => `${scope}/${KEYWORDS.action}/${actionId}`
const identifier = (namespace, keyPath) => `2-${namespace}-${keyPath}`
const KEY_PATHS = {
  // One key path per record on both curves (KEYS §1.6.1 level 3): the P-256 signing key and
  // recipient keys (ENV §8.5, §8.6) and the secp256k1 commitment key (ANC §3.1).
  record: actionOf(SCOPE, IDS.recordId),
  record2: actionOf(SCOPE, IDS.secondRecordId),
  field: `${actionOf(SCOPE, IDS.recordId)}/field/${IDS.fieldName}`,
  session: `${SCOPE}/${KEYWORDS.session}/${IDS.sessionId}`,
  // KEYS §1.6.1 level-4 purposes `handoff` and `topup`.
  handoff: `${actionOf(SCOPE, IDS.recordId)}/handoff/${IDS.refIdHex}`,
  topup: `${actionOf(SCOPE, IDS.recordId)}/topup/0`
}
const PATHS = {
  sign: identifier(NAMESPACES.sign, KEY_PATHS.record),
  sign2: identifier(NAMESPACES.sign, KEY_PATHS.record2),
  encrypt: identifier(NAMESPACES.encrypt, KEY_PATHS.record),
  field: identifier(NAMESPACES.encrypt, KEY_PATHS.field),
  session: identifier(NAMESPACES.delegate, KEY_PATHS.session),
  // The actor's persistent key: `2-sdx delegate-actor/<index>`, counterparty self.
  actor: index => identifier(NAMESPACES.delegate, `${KEYWORDS.actor}/${index}`),
  // ANC §3.1: the commitment key is the record's signing-namespace identifier, on secp256k1.
  commitment: identifier(NAMESPACES.sign, KEY_PATHS.record),
  nextCommitment: identifier(NAMESPACES.sign, KEY_PATHS.record2),
  handoff: identifier(NAMESPACES.handoff, KEY_PATHS.handoff),
  topup: identifier(NAMESPACES.sign, KEY_PATHS.topup),
  secondSign: identifier(NAMESPACES.sign, actionOf(scopeOf(A2_ID), IDS.recordId)),
  secondCommitment: identifier(NAMESPACES.sign, actionOf(scopeOf(A2_ID), IDS.recordId))
}
// KEYS §1.6.1's delegation variant, which the module does not serve (refusal cases only).
const delegationPath = actorHex => identifier(NAMESPACES.delegate, `${SCOPE}/${KEYWORDS.delegation}/${IDS.delId}/${KEYWORDS.actor}/${actorHex}`)
const splitIdentifier = text => {
  const match = /^([0-2])-([^-]+)-(.+)$/s.exec(text)
  if (!match) fail(`identifier ${text}`)
  return { level: Number(match[1]), namespace: match[2], keyPath: match[3] }
}

// The account tag: the 32-character lowercase hex of the first 16 bytes of
// SHA-256(UTF-8 account ID). The logical protocol ID is `<role> <tag>`.
const SCHEME = 'p sdx'
const tagOf = acct => hex(sha256(utf8(acct)).subarray(0, 16))
const TAGS = { [A_ID]: tagOf(A_ID), [A2_ID]: tagOf(A2_ID), [NEW_ID]: tagOf(NEW_ID), [B_ID]: tagOf(B_ID) }
const logicalOf = (role, acct) => `${role} ${tagOf(acct)}`
const protocolNameOf = (operation, role, acct) => `${SCHEME} ${operation} ${logicalOf(role, acct)}`

// Grant prefixes end at a '/' so that one account ID cannot cover another
// account ID that extends it.
const PREFIXES = {
  sign: `2-${NAMESPACES.sign}-account/${A_ID}/`,
  encrypt: `2-${NAMESPACES.encrypt}-account/${A_ID}/`,
  delegate: `2-${NAMESPACES.delegate}-account/${A_ID}/`,
  handoff: `2-${NAMESPACES.handoff}-account/${A_ID}/`,
  actor: `2-${NAMESPACES.delegate}-actor/`,
  secondSign: `2-${NAMESPACES.sign}-account/${A2_ID}/`,
  newSign: `2-${NAMESPACES.sign}-account/${NEW_ID}/`,
  recipientSign: `2-${NAMESPACES.sign}-account/${B_ID}/`
}
const grant = (wallet, operation, role, acct, prefixes) => ({ wallet, protocolID: [2, protocolNameOf(operation, role, acct)], prefixes })
const GRANTS = [
  grant('account', 'open', 'root', A_ID, []),
  grant('account', 'open', 'root', A2_ID, []),
  grant('account', 'open', 'root', NEW_ID, []),
  grant('account', 'key', 'write', A_ID, [PREFIXES.sign, PREFIXES.encrypt]),
  grant('account', 'key', 'read', A_ID, [PREFIXES.sign, PREFIXES.encrypt]),
  grant('account', 'key', 'root', A_ID, [PREFIXES.sign, PREFIXES.encrypt]),
  grant('account', 'peer', 'write', A_ID, [PREFIXES.sign, PREFIXES.encrypt]),
  grant('account', 'sign', 'write', A_ID, [PREFIXES.sign]),
  grant('account', 'decrypt', 'read', A_ID, [PREFIXES.encrypt]),
  grant('account', 'key', 'write', A2_ID, [PREFIXES.secondSign]),
  grant('account', 'sign', 'write', A2_ID, [PREFIXES.secondSign]),
  grant('account', 'key', 'write', NEW_ID, [PREFIXES.newSign]),
  grant('account', 'k1key', 'write', A_ID, [PREFIXES.sign, PREFIXES.handoff]),
  grant('account', 'k1key', 'read', A_ID, [PREFIXES.sign, PREFIXES.handoff]),
  grant('account', 'k1peer', 'write', A_ID, [PREFIXES.handoff]),
  grant('account', 'k1sign', 'write', A_ID, [PREFIXES.sign]),
  grant('account', 'k1key', 'write', A2_ID, [PREFIXES.secondSign]),
  grant('account', 'k1sign', 'write', A2_ID, [PREFIXES.secondSign]),
  grant('account', 'k1key', 'write', NEW_ID, [PREFIXES.newSign]),
  grant('recipient', 'key', 'read', B_ID, [PREFIXES.encrypt]),
  grant('recipient', 'decrypt', 'read', B_ID, [PREFIXES.encrypt]),
  grant('recipient', 'k1key', 'write', B_ID, [PREFIXES.handoff]),
  grant('recipient', 'k1key', 'write', A_ID, [PREFIXES.handoff]),
  grant('recipient', 'k1sign', 'write', B_ID, [PREFIXES.handoff]),
  grant('recipient', 'sign', 'root', B_ID, [PREFIXES.recipientSign]),
  grant('actor', 'key', 'actor', A_ID, [PREFIXES.actor]),
  grant('actor', 'sign', 'actor', A_ID, [PREFIXES.actor]),
  grant('actor', 'key', 'session', A_ID, [PREFIXES.delegate]),
  grant('actor', 'sign', 'session', A_ID, [PREFIXES.delegate]),
  grant('actor', 'k1key', 'actor', A_ID, [PREFIXES.actor]),
  grant('actor', 'k1key', 'session', A_ID, [PREFIXES.delegate])
]

// Results of components/sdx/p256/grind (4 workers; the smallest hit is
// reported independent of thread timing). Re-verified below on every run.
const GRIND_PATH_COUNTER = 6019505901, GRIND_PATH_TRIES = 6026497378, GRIND_PATH_SECONDS = 284
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const crockford16 = counter => Array.from({ length: 16 }, (_, i) => CROCKFORD[Number((BigInt(counter) >> BigInt(5 * (15 - i))) & 31n)]).join('')
const GRIND = {
  tool: 'components/sdx/p256/grind/main.go',
  seed: { command: 'seed', prefix: 'ff'.repeat(56), label: LABELS.p256, counter: 1557900713, tries: 1558038232, workers: 4, wallSeconds: 139, smallest: true },
  path: { command: 'path', prefix: PATHS.sign.slice(0, -16), counter: GRIND_PATH_COUNTER, tries: GRIND_PATH_TRIES, workers: 4, wallSeconds: GRIND_PATH_SECONDS, smallest: true }
}
GRIND.seed.ikm = GRIND.seed.prefix + GRIND.seed.counter.toString(16).padStart(16, '0')
GRIND.path.identifier = GRIND.path.prefix + crockford16(GRIND.path.counter)

// ---- roots ----------------------------------------------------------------

function makeRoot(ikm) {
  const secp256k1Seed = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.secp256k1), 32)
  const p256Seed = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.p256), 32)
  const usable = { secp256k1: toBig(secp256k1Seed) > 0n && toBig(secp256k1Seed) < NK, p256: toBig(p256Seed) > 0n && toBig(p256Seed) < N }
  const root = { ikm, secp256k1Seed, p256Seed, usable }
  if (usable.secp256k1 && usable.p256) {
    root.secp256k1PublicKey = secp256k1.getPublicKey(secp256k1Seed, true)
    root.p256PublicKey = p256.getPublicKey(p256Seed, true)
    if (PrivateKey.fromHex(hex(secp256k1Seed)).toPublicKey().toString() !== hex(root.secp256k1PublicKey)) fail('secp256k1 identity: noble vs @bsv/sdk')
  }
  return root
}
const ROOT_NAMES = ['account', 'recipient', 'actor', 'session']
const ROOTS = Object.fromEntries(ROOT_NAMES.map((name, i) => [name, makeRoot(Uint8Array.from({ length: 64 }, (_, j) => 64 * i + j))]))
ROOTS.unusable = makeRoot(unhex(GRIND.seed.ikm))
if (!ROOTS.unusable.usable.secp256k1 || ROOTS.unusable.usable.p256) fail('grind seed hit')
for (const name of ROOT_NAMES) if (!ROOTS[name].usable.secp256k1 || !ROOTS[name].usable.p256) fail(`root ${name}`)
const { account: A, recipient: B, actor: C, session: D } = ROOTS

// Accounts created in a wallet (draft §Canonical derivation step 1): the wallet derives the
// account's ikm from its own root. d is the BRC-42 child private key under the BRC-44 admin
// protocol [2, "admin sdx root"], key ID "<accountId> <epoch>" (or "actor" for an actor root),
// counterparty self, and the ikm is HKDF-SHA-256(IKM = d as 32 bytes big-endian, salt "p sdx v1",
// info "sdx root", L = 64). The KEYS §1.4.2 split then runs unchanged.
const WALLET_ROOT_PROTOCOL = Object.freeze([2, 'admin sdx root'])
const WALLET_ROOT_SALT = 'p sdx v1'
const WALLET_ROOT_INFO = 'sdx root'
const WALLET_ROOT_LABEL = 'TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: wallet root'
const WALLET_ROOT = sha256(utf8(WALLET_ROOT_LABEL))
function walletDerivedRoot(walletRoot, keyID) {
  const invoice = `${WALLET_ROOT_PROTOCOL[0]}-${WALLET_ROOT_PROTOCOL[1]}-${keyID}`
  // noble: shared point r·(r·G), HMAC-SHA-256 keyed by its compressed encoding, d = r + HMAC mod n.
  const shared = secp256k1.getSharedSecret(walletRoot, secp256k1.getPublicKey(walletRoot, true), true)
  const mac = hmac(sha256, shared, utf8(invoice))
  const d = be32((toBig(walletRoot) + toBig(mac)) % NK)
  // @bsv/sdk: the same child private key through KeyDeriver.
  const sdkChild = new KeyDeriver(PrivateKey.fromHex(hex(walletRoot))).derivePrivateKey(WALLET_ROOT_PROTOCOL, keyID, 'self')
  if (sdkChild.toHex().padStart(64, '0') !== hex(d)) fail('wallet root d: noble vs @bsv/sdk')
  const ikm = hkdf(sha256, d, utf8(WALLET_ROOT_SALT), utf8(WALLET_ROOT_INFO), 64)
  const root = makeRoot(ikm)
  if (!root.usable.secp256k1 || !root.usable.p256) fail(`${keyID}: unusable ikm`)
  return { keyID, invoice, shared, mac, d, ikm, root }
}
const DERIVED = {
  secondEpoch0: walletDerivedRoot(WALLET_ROOT, `${A2_ID} 0`),
  secondEpoch1: walletDerivedRoot(WALLET_ROOT, `${A2_ID} 1`),
  rotation: walletDerivedRoot(WALLET_ROOT, `${A_ID} 1`),
  newAccount: walletDerivedRoot(WALLET_ROOT, `${NEW_ID} 0`),
  actor: walletDerivedRoot(WALLET_ROOT, 'actor')
}
{
  const ikms = new Set(Object.values(DERIVED).map(entry => hex(entry.ikm)))
  if (ikms.size !== Object.keys(DERIVED).length) fail('derived ikm repeats')
}

// Wallet state the module cases run against. Each case starts from this state.
const WALLETS = {
  account: {
    walletRoot: WALLET_ROOT,
    accounts: [
      { acct: A_ID, current: 0, epochs: [{ ep: 0, root: A }] },
      { acct: A2_ID, current: 1, epochs: [{ ep: 0, root: DERIVED.secondEpoch0.root, derived: true }, { ep: 1, root: DERIVED.secondEpoch1.root, derived: true }] }
    ]
  },
  recipient: { accounts: [{ acct: B_ID, current: 0, epochs: [{ ep: 0, root: B }] }] },
  actor: { accounts: [], actor: C, sessions: { [IDS.sessionId]: D } }
}
const sessionIdOf = text => /\/session\/([0-9a-f]{32})(?:\/|$)/.exec(text)?.[1]
function rootFor(walletName, role, acct, { ep, path: keyPathText } = {}) {
  const wallet = WALLETS[walletName]
  if (role === 'actor') return wallet.actor
  if (role === 'session') return wallet.sessions[sessionIdOf(keyPathText)]
  const account = wallet.accounts.find(entry => entry.acct === acct)
  return account.epochs.find(entry => entry.ep === (ep ?? account.current)).root
}

// ---- KEYS §1.8.2 on P-256 (noble) -----------------------------------------

function offset(seed, counterparty, id) {
  const shared = p256.getSharedSecret(seed, counterparty, true)
  const mac = hmac(sha256, shared, utf8(id))
  const h = toBig(mac)
  return { shared, mac, h, rejected: h === 0n || h >= N }
}
function own(seed, counterparty, id) {
  const o = offset(seed, counterparty, id)
  if (o.rejected) return o
  const d = (toBig(seed) + o.h) % N
  return { ...o, d, publicKey: p256.getPublicKey(be32(d), true) }
}
function theirs(seed, counterparty, id) {
  const o = offset(seed, counterparty, id)
  if (o.rejected) return o
  return { ...o, publicKey: point(counterparty).add(G.multiply(o.h)).toBytes(true) }
}
const intermediates = derived => ({
  sharedPoint: hex(derived.shared),
  hmac: hex(derived.mac),
  ...(derived.d === undefined ? {} : { childPrivate: hex(be32(derived.d)) })
})

// ---- BRC-42 on secp256k1 (noble, cross-checked against @bsv/sdk BRC-100) -------

function k1Offset(seed, counterparty, id) {
  const shared = secp256k1.getSharedSecret(seed, counterparty, true)
  const mac = hmac(sha256, shared, utf8(id))
  const h = toBig(mac)
  return { shared, mac, h, rejected: h === 0n || h >= NK }
}
function k1Own(seed, counterparty, id) {
  const o = k1Offset(seed, counterparty, id)
  if (o.rejected) fail(`secp256k1 offset rejected for ${id}`)
  const d = (toBig(seed) + o.h) % NK
  return { ...o, d, publicKey: secp256k1.getPublicKey(be32(d), true) }
}
function k1Theirs(seed, counterparty, id) {
  const o = k1Offset(seed, counterparty, id)
  if (o.rejected) fail(`secp256k1 offset rejected for ${id}`)
  return { ...o, publicKey: k1Point(counterparty).add(GK.multiply(o.h)).toBytes(true) }
}
// Stock BRC-100: a ProtoWallet whose root is the selected root's secp256k1 seed, with the
// SDX derivation identifier read as protocol [s, namespace] and key ID <keyPath>.
async function brc100PublicKey(root, operation, input) {
  const wallet = new ProtoWallet(new PrivateKey(hex(root.secp256k1Seed), 16))
  if (!('path' in input)) {
    const args = { identityKey: true }
    return { method: 'getPublicKey', args, publicKey: (await wallet.getPublicKey(args)).publicKey }
  }
  const { level, namespace, keyPath } = splitIdentifier(input.path)
  const args = { protocolID: [level, namespace], keyID: keyPath, counterparty: input.peer ? hex(input.peer) : 'self', ...(operation === 'k1key' ? { forSelf: true } : {}) }
  return { method: 'getPublicKey', args, publicKey: (await wallet.getPublicKey(args)).publicKey }
}
async function brc100Signature(root, input) {
  const wallet = new ProtoWallet(new PrivateKey(hex(root.secp256k1Seed), 16))
  const { level, namespace, keyPath } = splitIdentifier(input.path)
  const args = { hashToDirectlySign: Array.from(input.hash), protocolID: [level, namespace], keyID: keyPath, counterparty: input.peer ? hex(input.peer) : 'self' }
  const { signature } = await wallet.createSignature(args)
  return { method: 'createSignature', args: { ...args, hashToDirectlySign: hex(input.hash) }, signature: hex(signature) }
}

// The path search ran against the account root's self HMAC key, r·(r·G).
GRIND.path.hmacKey = hex(offset(A.p256Seed, A.p256PublicKey, PATHS.sign).shared)
if (GRIND.path.hmacKey !== '02be4bdb55e891f95b60c45c0c2c53ff8b60a9a2e0a2f8d0d664d8abc67ff56d14') fail('grind HMAC key')
if (!offset(A.p256Seed, A.p256PublicKey, GRIND.path.identifier).rejected) fail('grind path hit')

// ---- deterministic CBOR inputs ---------------------------------------------

// JSON view of a CBOR input: `path` and `acct` are text, `ep` is an unsigned
// integer (a JSON number), and every other member is bytes (hex). A member of
// another major type is written {"tstr": ...}, {"bstr": hex}, {"uint": n} or
// {"nint": n}, so that malformed inputs stay representable.
// `jwe` is a map of text keys to text values and maps, written in JSON as itself.
const MEMBER_TYPES = { path: 'tstr', acct: 'tstr', ep: 'uint', jwe: 'map' }
const typeOf = name => MEMBER_TYPES[name] ?? 'bstr'
function encodeInput(fields) {
  const bytes = cborEncode(fields, rfc8949EncodeOptions)
  const back = cborDecode(bytes)
  if (Object.keys(back).length !== Object.keys(fields).length || hex(cborEncode(back, rfc8949EncodeOptions)) !== hex(bytes)) fail('CBOR round trip')
  for (const [name, value] of Object.entries(fields)) {
    if (value instanceof Uint8Array ? hex(back[name]) !== hex(value) : typeof value === 'object' ? JSON.stringify(back[name]) !== JSON.stringify(sortedJson(value)) : back[name] !== value) fail(`CBOR member ${name}`)
  }
  return bytes
}
// A map with its keys in RFC 8949 §4.2.1 order (shorter keys first, then bytewise), as decoded.
function sortedJson(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return value
  const order = (a, b) => a.length - b.length || (a < b ? -1 : a > b ? 1 : 0)
  return Object.fromEntries(Object.keys(value).sort(order).map(key => [key, sortedJson(value[key])]))
}
function jsonMember(name, value) {
  const natural = typeOf(name)
  if (value !== null && typeof value === 'object' && !(value instanceof Uint8Array)) {
    if (natural !== 'map') fail(`member ${name}`)
    return value
  }
  if (typeof value === 'string') return natural === 'tstr' ? value : { tstr: value }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail(`member ${name}`)
    if (value < 0) return { nint: value }
    return natural === 'uint' ? value : { uint: value }
  }
  return natural === 'bstr' ? hex(value) : { bstr: hex(value) }
}
const jsonInput = fields => Object.fromEntries(Object.entries(fields).map(([name, value]) => [name, jsonMember(name, value)]))
const entryBytes = fields => encodeInput(fields).subarray(1) // one map entry without the map head

function request(method, protocolName, fields, extra = {}) {
  const carrier = method === 'decrypt' ? 'ciphertext' : 'plaintext'
  return {
    method,
    args: { protocolID: [2, protocolName], keyID: '1', counterparty: 'self', [carrier]: hex(encodeInput(fields)), ...extra },
    input: jsonInput(fields)
  }
}
const carrierOf = operation => operation === 'decrypt' ? 'decrypt' : 'encrypt'
const moduleRequest = (operation, role, acct, fields, extra) => request(carrierOf(operation), protocolNameOf(operation, role, acct), fields, extra)

// ---- ES256 (noble, RFC 6979, then low-S per KEYS §1.8.3) ----------------------

function es256(d, message) {
  const signature = p256.sign(message, be32(d), { lowS: true })
  const raw = p256.sign(message, be32(d), { lowS: false })
  const publicKey = p256.getPublicKey(be32(d), true)
  if (signature.length !== 64 || !p256.verify(signature, message, publicKey, { lowS: true }) || !p256.verify(raw, message, publicKey, { lowS: false })) fail('ES256 sign')
  const rawS = toBig(raw.subarray(32)), s = toBig(signature.subarray(32))
  const normalised = rawS > N / 2n
  if (hex(raw.subarray(0, 32)) !== hex(signature.subarray(0, 32)) || s !== (normalised ? N - rawS : rawS) || s > N / 2n) fail('low-S relation')
  return { signature, raw, normalised }
}
function signingInput(kidHex, payloadText) {
  return `${b64u(utf8(JSON.stringify({ alg: 'ES256', kid: kidHex })))}.${b64u(utf8(payloadText))}`
}

// ---- secp256k1 ECDSA (noble RFC 6979 over the given 32 bytes, low-S, DER) --------

function k1Sign(d, hash) {
  const der = secp256k1.sign(hash, be32(d), { prehash: false, lowS: true, format: 'der' })
  const raw = secp256k1.sign(hash, be32(d), { prehash: false, lowS: false, format: 'compact' })
  const publicKey = secp256k1.getPublicKey(be32(d), true)
  if (!secp256k1.verify(der, hash, publicKey, { prehash: false, format: 'der' })) fail('secp256k1 sign')
  const sdk = ECDSA.sign(new BigNumber(Array.from(hash)), new BigNumber(hex(be32(d)), 16), true)
  if (hex(sdk.toDER()) !== hex(der)) fail('secp256k1 signature: noble vs @bsv/sdk')
  const rawS = toBig(raw.subarray(32))
  return { signature: der, raw, normalised: rawS > NK / 2n }
}

// ---- ECDH-ES+A256KW JWEs (jose), frozen -------------------------------------

const affineJwk = (pub, d) => {
  const { x, y } = point(pub).toAffine()
  return { kty: 'EC', crv: 'P-256', x: b64u(be32(x)), y: b64u(be32(y)), ...(d === undefined ? {} : { d: b64u(be32(d)) }) }
}
// RFC 7518 §4.6.2 Concat KDF for A256KW (one SHA-256 block). The generator
// checks the result by AES key unwrap of jose's encrypted_key below.
function concatKek(z, apu, apv) {
  const length32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
  const other = Buffer.concat([length32(14), Buffer.from('ECDH-ES+A256KW'), length32(apu.length), apu, length32(apv.length), apv, length32(256)])
  return sha256(Buffer.concat([length32(1), Buffer.from(z), other]))
}
const aesKeyUnwrap = (kek, ek) => {
  const unwrap = createDecipheriv('id-aes256-wrap', kek, Buffer.from('a6a6a6a6a6a6a6a6', 'hex'))
  return Buffer.concat([unwrap.update(ek), unwrap.final()])
}
// A general JWE (RFC 7516 §7.2.1) as an SDX encoder writes one (ENV §5.2, §9): A256GCM content and
// one ECDH-ES+A256KW recipient per kid, each with the unprotected header {alg, kid}. jose draws the
// content-encryption key, the IV and each ephemeral key at random, so the JWE is made once with
// --write and frozen with the inputs it was made for and its content-encryption key.
async function frozenJwe(frozen, name, protectedHeader, recipients, plaintext) {
  const binding = { protectedHeader, kids: recipients.map(r => hex(r.kid)), plaintext: hex(plaintext) }
  const stored = frozen.jwe[name]
  if (!stored || JSON.stringify(stored.binding) !== JSON.stringify(binding)) {
    if (mode !== '--write') fail(`frozen JWE ${name} is missing or was made for other inputs; run --write`)
    const encryptor = new jose.GeneralEncrypt(plaintext).setProtectedHeader(protectedHeader)
    for (const { kid } of recipients) encryptor.addRecipient(await jose.importJWK(affineJwk(kid), 'ECDH-ES+A256KW')).setUnprotectedHeader({ alg: 'ECDH-ES+A256KW', kid: hex(kid) })
    const jwe = await encryptor.encrypt()
    const cek = (await openEntry(entryOf(jwe, 0), recipients[0], plaintext, name)).cek
    frozen.jwe[name] = { binding, cek: hex(cek), jwe }
    frozen.changed = true
  }
  frozen.used.add(name)
  const { jwe, cek } = frozen.jwe[name]
  if (jwe.recipients.length !== recipients.length) fail(`frozen JWE ${name} recipients`)
  const opened = []
  for (const [i, recipient] of recipients.entries()) {
    const entry = entryOf(jwe, i)
    if (entry.header.kid !== hex(recipient.kid)) fail(`frozen JWE ${name} kid ${i}`)
    const step = await openEntry(entry, recipient, plaintext, `${name}[${i}]`)
    if (hex(step.cek) !== cek) fail(`frozen JWE ${name} CEK`)
    opened.push({ entry, ...step })
  }
  // jose writes epk in the protected header for one recipient and in each recipient's header for several.
  const inProtected = 'epk' in JSON.parse(Buffer.from(jwe.protected, 'base64url'))
  if (inProtected !== (recipients.length === 1)) fail(`frozen JWE ${name}: epk placement`)
  return { jwe, cek: unhex(cek), opened }
}
// One recipient's flattened entry (RFC 7516 §7.2.2), the form `decrypt` takes.
const entryOf = (jwe, i) => ({ protected: jwe.protected, header: jwe.recipients[i].header, encrypted_key: jwe.recipients[i].encrypted_key, iv: jwe.iv, ciphertext: jwe.ciphertext, tag: jwe.tag })
const jointHeader = entry => ({ ...JSON.parse(Buffer.from(entry.protected, 'base64url').toString('utf8')), ...entry.header })
const epkOf = entry => {
  const { x, y } = jointHeader(entry).epk
  return p256.Point.fromAffine({ x: toBig(Buffer.from(x, 'base64url')), y: toBig(Buffer.from(y, 'base64url')) }).toBytes(true)
}
// The key agreement of one entry with a candidate child key: Z, the key-encryption key and the AES
// key unwrap, by node:crypto; for the right key also jose's decryption and node:crypto's AES-GCM.
async function openEntry(entry, { kid, d }, plaintext, what) {
  const z = p256.getSharedSecret(be32(d), epkOf(entry), true).subarray(1)
  const kek = concatKek(z, new Uint8Array(0), new Uint8Array(0))
  const cek = aesKeyUnwrap(kek, Buffer.from(entry.encrypted_key, 'base64url'))
  const opened = await jose.flattenedDecrypt(entry, await jose.importJWK(affineJwk(kid, d), 'ECDH-ES+A256KW'), { keyManagementAlgorithms: ['ECDH-ES+A256KW'], contentEncryptionAlgorithms: ['A256GCM'] })
  same(opened.plaintext, plaintext, `JWE ${what} by jose`)
  const gcm = createDecipheriv('aes-256-gcm', cek, Buffer.from(entry.iv, 'base64url'))
  gcm.setAAD(Buffer.from(entry.protected, 'ascii'))
  gcm.setAuthTag(Buffer.from(entry.tag, 'base64url'))
  same(Buffer.concat([gcm.update(Buffer.from(entry.ciphertext, 'base64url')), gcm.final()]), plaintext, `JWE ${what} by node:crypto`)
  return { z, kek, cek }
}
// A wrong candidate key: its key-encryption key fails the AES key unwrap's integrity check.
function failedEntry(entry, d) {
  const z = p256.getSharedSecret(be32(d), epkOf(entry), true).subarray(1)
  const kek = concatKek(z, new Uint8Array(0), new Uint8Array(0))
  let unwrapped = true
  try { aesKeyUnwrap(kek, Buffer.from(entry.encrypted_key, 'base64url')) } catch { unwrapped = false }
  if (unwrapped) fail('a wrong key opened a JWE entry')
  return { z, kek }
}

// ---- shared document parts ---------------------------------------------------

// BRC texts are pinned by git blob in bsv-blockchain/BRCs, as the sibling suites pin them.
const BRC_BLOBS = {
  42: ['key-derivation/0042.md', '5ac0c735f524ccdcd0c2b020a4be0b38981e68db'],
  43: ['key-derivation/0043.md', '5eb00be6fe5fca5a982d5c29b99ec5de136fdc5d'],
  98: ['wallet/0098.md', 'a9696acf05a63c95199f4f90ca733719613e4b48'],
  229: ['wallet/0229.md', 'd5e9abd0672d53942e2bbbc351419ab2ab7522c0']
}
const brc = (number, clause) => ({ brc: number, repository: 'bsv-blockchain/BRCs', path: BRC_BLOBS[number][0], gitBlob: BRC_BLOBS[number][1], clause })
const DRAFT = 'fixtures/sdx/v1/standards/draft-statements/brc-draft-sdx-module.md'
const PROGRAM = 'programs/proposals/sdx-data-sharing/0.1.0/profile.json'
const KEYS = 'fixtures/sdx/v1/standards/text/keys.md'
const ENV = 'fixtures/sdx/v1/standards/text/envelope.md'
const ANC = 'fixtures/sdx/v1/standards/text/anchoring.md'
const publicKeys = root => ({ R: hex(root.p256PublicKey), K: hex(root.secp256k1PublicKey) })
const testKeys = names => ({
  note: 'Public test key material, not a secret, never funded. Each root is a fixed 64-byte ikm. LAB_SELF_TEST_ONLY.',
  labels: LABELS,
  roots: Object.fromEntries(names.map(name => {
    const root = ROOTS[name]
    return [name, root.usable.p256
      ? { ikm: hex(root.ikm), secp256k1Seed: hex(root.secp256k1Seed), p256Seed: hex(root.p256Seed), secp256k1PublicKey: hex(root.secp256k1PublicKey), p256PublicKey: hex(root.p256PublicKey) }
      : { ikm: hex(root.ikm), secp256k1Seed: hex(root.secp256k1Seed), p256Seed: hex(root.p256Seed), usable: false }]
  }))
})
const WALLETS_NOTE = 'Wallet state for replay. Every module case names one wallet and starts from the state below; no case sees another case\'s effects. An account epoch is either an `ikm` (64 bytes, imported or fixed) or `{walletRoot, derived: true}`: its ikm is derived from that wallet root with `walletRootDerivation` and key ID "<acct> <ep>". `current` is the epoch used when a request carries no `ep`. `actor` is the wallet\'s actor root, and `sessions` maps a session ID (the hex `<sessionId>` segment of a session path) to that session\'s root. `R` and `K` are the P-256 and secp256k1 root public keys of each root, for checking a loaded state. `grants` are the standing grants of the one laboratory originator: a request reaches derivation only under a grant whose protocolID equals its own and, when it carries `path`, under one of its derivation-identifier prefixes. A case with `prompt: "approve"` runs as if the user approved the prompt the request raises.'
function walletsTable(names) {
  const epochEntry = entry => ({ ep: entry.ep, ...(entry.derived ? { walletRoot: hex(WALLET_ROOT), derived: true } : { ikm: hex(entry.root.ikm) }), ...publicKeys(entry.root) })
  const entries = {}
  for (const name of names) {
    const wallet = WALLETS[name]
    entries[name] = {
      ...(wallet.walletRoot ? { walletRoot: hex(wallet.walletRoot) } : {}),
      accounts: wallet.accounts.map(account => ({ acct: account.acct, tag: tagOf(account.acct), current: account.current, epochs: account.epochs.map(epochEntry) })),
      ...(wallet.actor ? { actor: { ikm: hex(wallet.actor.ikm), ...publicKeys(wallet.actor) } } : {}),
      ...(wallet.sessions ? { sessions: Object.fromEntries(Object.entries(wallet.sessions).map(([id, root]) => [id, { ikm: hex(root.ikm), ...publicKeys(root) }])) } : {}),
      grants: GRANTS.filter(entry => entry.wallet === name).map(({ protocolID, prefixes }) => ({ protocolID, prefixes }))
    }
  }
  return {
    note: WALLETS_NOTE,
    profile: { labels: LABELS, namespaces: REGISTERED, keywords: KEYWORDS, purposes: PURPOSES },
    walletRootDerivation: { protocolID: [...WALLET_ROOT_PROTOCOL], keyID: '<acct> <ep>', counterparty: 'self', salt: WALLET_ROOT_SALT, info: WALLET_ROOT_INFO, length: 64 },
    entries
  }
}
const profile = () => ({
  note: 'The laboratory deployment profile, copied from `file` (KEYS §1.3.1; ENV §2.1), LAB_SELF_TEST_ONLY. The labels, namespaces, key-path keywords, purposes and credential type are SDX\'s example values, used for the laboratory only; the format identifier is the laboratory\'s own. One level-3 keyword, `action`, names a record on both curves (decision D-PROFILE). `actor` is also the keyword of the actor\'s persistent key path `actor/<index>` (module draft, step 1). The credential type is not an input to any case of this suite. The identifiers are the worked example of KEYS §1.8.1.',
  file: PROFILE_FILE,
  formatIdentifier: FORMAT_IDENTIFIER,
  credentialType: CREDENTIAL_TYPE,
  labels: LABELS,
  namespaces: NAMESPACES,
  keywords: KEYWORDS,
  purposes: PURPOSES,
  identifiers: IDS,
  accountTags: TAGS,
  logicalProtocolIDs: Object.fromEntries(['write', 'read', 'root', 'actor', 'session'].map(role => [role, logicalOf(role, A_ID)]))
})
const generator = () => ({
  path: 'components/sdx/p256/generate.mjs',
  package: 'components/sdx/p256/package.json',
  lockfile: 'components/sdx/p256/package-lock.json',
  runtime: `node ${process.versions.node}`,
  dependencies: { '@bsv/sdk': '4.0.1', '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0', cborg: '6.1.3', jose: '5.10.0' },
  deterministic: 'Every value except the JWEs that `decrypt` cases open is regenerated byte for byte by `node generate.mjs --check`.',
  frozen: { path: 'components/sdx/p256/frozen.json', parts: 'The JWEs that `decrypt` cases open, made by jose 5.10.0 GeneralEncrypt with a random content-encryption key, IV and ephemeral key per recipient, and stored with the protected header, recipient kids and plaintext they were made for and their content-encryption key. They were generated once and are re-verified by decryption, with jose and with node:crypto, on every run.' },
  grind: GRIND
})
const P256_ORACLES = () => [
  { path: 'src/sdx/p256.mjs', basis: 'node:crypto', coverage: 'Every case. OpenSSL performs scalar multiplication, ECDH, HKDF, HMAC, ES256 verification, AES key unwrap and AES-GCM; src/sdx/ec-p256.mjs adds point validation, y recovery and point addition in BigInt; src/sdx/brc42.mjs supplies the secp256k1 BRC-42 steps. RFC 6979 nonces are recomputed with node:crypto HMAC.' },
  { path: 'test/sdx_ec.py', basis: 'python stdlib', coverage: 'Every value, with test/sdx_module.py, including each JWE decryption: test/sdx_ec.py carries its own AES-256 (FIPS 197), AES key unwrap (RFC 3394) and AES-GCM (SP 800-38D), checked against their published known answers.' }
]
const K1_ORACLES = () => [
  { path: 'src/sdx/k1.mjs', basis: 'node:crypto', coverage: 'Every case, through the module semantics of src/sdx/p256.mjs. OpenSSL performs scalar multiplication and HMAC; src/sdx/ec-p256.mjs adds point validation and addition; src/sdx/brc42.mjs independently recomputes every BRC-100 getPublicKey result; src/sdx/tx.mjs recomputes the transaction preimage and evaluates the spend. RFC 6979 nonces are recomputed with node:crypto HMAC.' },
  { path: 'test/sdx_ec.py', basis: 'python stdlib', coverage: 'Every value: child keys, BRC-100 results, RFC 6979 nonces, DER signatures and their verification, injected offsets, request rules and the transaction preimage hash.' }
]

// ---- VC-P256 -------------------------------------------------------------

// The JWE entries the decrypt cases open, shared with the point and request rejections.
const decryptContext = {}

async function buildVc(frozen) {
  const cases = []
  const add = entry => cases.push(entry)

  for (const name of ROOT_NAMES) {
    const root = ROOTS[name]
    add({
      id: `split-${name}`, requirement: 'P256-01', kind: 'split',
      title: `Root split of the ${name} root (KEYS §1.4.2)`,
      root: name,
      input: { ikm: hex(root.ikm), labels: LABELS },
      expected: { secp256k1Seed: hex(root.secp256k1Seed), p256Seed: hex(root.p256Seed), secp256k1PublicKey: hex(root.secp256k1PublicKey), p256PublicKey: hex(root.p256PublicKey) }
    })
  }
  add({
    id: 'split-unusable-p256-seed', requirement: 'P256-01', kind: 'split',
    title: 'An ikm whose P-256 seed is >= n is unusable: the wallet aborts and never clamps (KEYS §1.4.3)',
    root: 'unusable',
    input: { ikm: hex(ROOTS.unusable.ikm), labels: LABELS },
    expected: { error: 'ikm-unusable', curve: 'P-256' },
    intermediate: { secp256k1Seed: hex(ROOTS.unusable.secp256k1Seed), p256Seed: hex(ROOTS.unusable.p256Seed) },
    found: 'grind seed: ikm = 0xff * 56 || uint64be(counter); see generator.grind.seed'
  })
  const walletCases = [
    ['wallet-root-epoch-0', DERIVED.secondEpoch0, `Account root derived inside a wallet, epoch 0 of ${A2_ID}: d is the BRC-42 child private key under [2, "admin sdx root"], key ID "<accountId> <epoch>", counterparty self; ikm = HKDF-SHA-256(d, salt "p sdx v1", info "sdx root", 64); then the KEYS §1.4.2 split. The account wallet holds this epoch`],
    ['wallet-root-epoch-1', DERIVED.secondEpoch1, `The same wallet and account at epoch 1: a different d and an unrelated ikm. It is the account's current epoch in the account wallet`],
    ['wallet-root-rotation', DERIVED.rotation, `Epoch 1 of the imported account ${A_ID}, as \`open\` creates it from the wallet root when the account rotates (case open-creates-epoch)`],
    ['wallet-root-new-account', DERIVED.newAccount, `Epoch 0 of a new account ${NEW_ID}, as \`open\` creates it (case open-creates-account)`],
    ['wallet-root-actor', DERIVED.actor, 'The actor root of a wallet that acts for an account: the same construction with key ID "actor" (draft step 1, "Actor wallets"). The actor cases of these suites start from a fixed actor root instead']
  ]
  for (const [id, derived, title] of walletCases) {
    add({
      id, requirement: 'P256-01', kind: 'wallet-root',
      title,
      input: { walletRootPrivateKey: hex(WALLET_ROOT), walletRootLabel: WALLET_ROOT_LABEL, protocolID: [...WALLET_ROOT_PROTOCOL], keyID: derived.keyID, counterparty: 'self', salt: WALLET_ROOT_SALT, info: WALLET_ROOT_INFO, labels: LABELS },
      expected: { d: hex(derived.d), ikm: hex(derived.ikm), secp256k1Seed: hex(derived.root.secp256k1Seed), p256Seed: hex(derived.root.p256Seed), secp256k1PublicKey: hex(derived.root.secp256k1PublicKey), p256PublicKey: hex(derived.root.p256PublicKey) },
      intermediate: { invoiceNumber: derived.invoice, sharedPoint: hex(derived.shared), hmac: hex(derived.mac) }
    })
  }
  for (const [curve, n] of [['secp256k1', NK], ['p256', N]]) {
    add({
      id: `seed-range-${curve}`, requirement: 'P256-01', kind: 'seed-range',
      title: `Injected ${curve} seeds: [1, n - 1] is accepted, everything else aborts (KEYS §1.4.3)`,
      curve, injected: true,
      values: [[0n, 'reject'], [1n, 'accept'], [n - 1n, 'accept'], [n, 'reject'], [(1n << 256n) - 1n, 'reject']].map(([v, expected]) => ({ seed: hex(be32(v)), expected }))
    })
    if (curve === 'p256') add({
      id: `offset-range-${curve}`, requirement: 'P256-01', kind: 'offset-range',
      title: `Injected ${curve} HMAC outputs: 0 and values >= n fail, 1 and n - 1 are accepted, nothing is reduced (KEYS §1.12 item 7; the reading of KEYS §1.8.2 in decision D-OFFSET)`,
      curve, injected: true,
      values: [[0n, 'reject'], [1n, 'accept'], [n - 1n, 'accept'], [n, 'reject'], [n + 1n, 'reject'], [(1n << 256n) - 1n, 'reject']].map(([v, expected]) => ({ hmac: hex(be32(v)), expected }))
    })
  }

  // open: an account's root public keys R || K, and account or epoch creation.
  const openCase = (id, title, acct, fields, root, extra = {}) => add({
    id, requirement: 'P256-01', kind: 'module', title,
    wallet: 'account',
    request: moduleRequest('open', 'root', acct, fields),
    expected: { ciphertext: hex(root.p256PublicKey) + hex(root.secp256k1PublicKey) },
    ...extra
  })
  openCase('open-imported-account', `\`open\`: the wallet holds the imported account ${A_ID} at epoch 0 and returns R || K, 66 bytes (Roots and selection)`, A_ID, { acct: A_ID }, A)
  openCase('open-current-epoch', `\`open\` without \`ep\`: the current epoch of ${A2_ID}, the highest opened (1)`, A2_ID, { acct: A2_ID }, DERIVED.secondEpoch1.root, { matches: 'wallet-root-epoch-1' })
  openCase('open-earlier-epoch', `\`open\` with \`ep\` 0: the older epoch of ${A2_ID} stays available for replay`, A2_ID, { acct: A2_ID, ep: 0 }, DERIVED.secondEpoch0.root, { matches: 'wallet-root-epoch-0' })
  openCase('open-creates-epoch', `\`open\` for epoch 1 of ${A_ID}, which the wallet does not hold: the wallet derives the new epoch from its own root (a rotation's new root, KEYS §1.10.2). Creation always prompts; the user approves`, A_ID, { acct: A_ID, ep: 1 }, DERIVED.rotation.root, { prompt: 'approve', matches: 'wallet-root-rotation' })
  openCase('open-creates-account', `\`open\` for a new account ${NEW_ID}: the wallet derives epoch 0 from its own root. Creation always prompts, even under a standing grant for \`open\`; the user approves`, NEW_ID, { acct: NEW_ID }, DERIVED.newAccount.root, { prompt: 'approve', matches: 'wallet-root-new-account' })

  add({
    id: 'key-root-public-key', requirement: 'P256-01', kind: 'module',
    title: '`key` without `path` returns the P-256 root public key R = p256_seed·G of the selected account, with no derivation',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, {}),
    expected: { ciphertext: hex(A.p256PublicKey) }
  })
  // Record signing key (ENV §8.5): self-derived under the signing namespace.
  const kid = own(A.p256Seed, A.p256PublicKey, PATHS.sign)
  add({
    id: 'key-record-signing-self', requirement: 'P256-01', kind: 'module',
    title: '`key`: the account record signing key under the signing namespace, counterparty self (ENV §8.5)',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: PATHS.sign }),
    expected: { ciphertext: hex(kid.publicKey) },
    intermediate: intermediates(kid)
  })
  add({
    id: 'key-record-signing-invariance', requirement: 'P256-01', kind: 'module',
    title: 'The key depends on the selected root and `path` only: roles write, read and root select the same account root, and keyID selects nothing',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: PATHS.sign }),
    variants: [{ protocolID: [2, protocolNameOf('key', 'read', A_ID)] }, { protocolID: [2, protocolNameOf('key', 'root', A_ID)] }, { keyID: 'another key id' }],
    expected: { ciphertext: hex(kid.publicKey) },
    sameAs: 'key-record-signing-self'
  })
  add({
    id: 'key-self-equals-own-root-as-peer', requirement: 'P256-01', kind: 'module',
    title: '`key` with `peer` set to the account\'s own P-256 root equals `key` without `peer` (self)',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: PATHS.sign, peer: A.p256PublicKey }),
    expected: { ciphertext: hex(own(A.p256Seed, A.p256PublicKey, PATHS.sign).publicKey) },
    sameAs: 'key-record-signing-self'
  })
  const composed = identifier(NAMESPACES.encrypt, `${KEY_PATHS.record}/field/caf\u00e9`)
  const decomposed = identifier(NAMESPACES.encrypt, `${KEY_PATHS.record}/field/cafe\u0301`)
  const nfc = own(A.p256Seed, A.p256PublicKey, composed), nfd = own(A.p256Seed, A.p256PublicKey, decomposed)
  if (hex(nfc.publicKey) === hex(nfd.publicKey)) fail('normalisation pair')
  add({
    id: 'key-path-nfc', requirement: 'P256-01', kind: 'module',
    title: '`path` is used byte for byte: a field name in NFC (U+00E9)',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: composed }),
    expected: { ciphertext: hex(nfc.publicKey) },
    intermediate: intermediates(nfc)
  })
  add({
    id: 'key-path-nfd', requirement: 'P256-01', kind: 'module',
    title: '`path` is used byte for byte: the same field name in NFD (e + U+0301) derives a different key; the module does not normalise',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: decomposed }),
    expected: { ciphertext: hex(nfd.publicKey) },
    intermediate: intermediates(nfd),
    differsFrom: 'key-path-nfc'
  })

  // Two accounts and two epochs in one wallet (Roots and selection).
  const second0 = DERIVED.secondEpoch0.root, second1 = DERIVED.secondEpoch1.root
  add({
    id: 'key-second-account-root', requirement: 'P256-01', kind: 'module',
    title: `Two accounts in one wallet: the tag of ${A2_ID} selects that account, at its current epoch 1`,
    wallet: 'account',
    request: moduleRequest('key', 'write', A2_ID, {}),
    expected: { ciphertext: hex(second1.p256PublicKey) },
    differsFrom: 'key-root-public-key'
  })
  add({
    id: 'key-second-account-epoch-1', requirement: 'P256-01', kind: 'module',
    title: '`ep` 1 names the current epoch, so the result equals the request without `ep`',
    wallet: 'account',
    request: moduleRequest('key', 'write', A2_ID, { ep: 1 }),
    expected: { ciphertext: hex(second1.p256PublicKey) },
    sameAs: 'key-second-account-root'
  })
  add({
    id: 'key-second-account-epoch-0', requirement: 'P256-01', kind: 'module',
    title: '`ep` 0 selects the older epoch, whose root differs',
    wallet: 'account',
    request: moduleRequest('key', 'write', A2_ID, { ep: 0 }),
    expected: { ciphertext: hex(second0.p256PublicKey) },
    differsFrom: 'key-second-account-root'
  })
  const secondKid1 = own(second1.p256Seed, second1.p256PublicKey, PATHS.secondSign)
  const secondKid0 = own(second0.p256Seed, second0.p256PublicKey, PATHS.secondSign)
  add({
    id: 'key-second-account-record', requirement: 'P256-01', kind: 'module',
    title: `\`key\`: a record signing key of ${A2_ID}, from its current epoch`,
    wallet: 'account',
    request: moduleRequest('key', 'write', A2_ID, { path: PATHS.secondSign }),
    expected: { ciphertext: hex(secondKid1.publicKey) },
    intermediate: intermediates(secondKid1)
  })
  add({
    id: 'key-second-account-record-epoch-0', requirement: 'P256-01', kind: 'module',
    title: 'The same path at epoch 0 derives from the epoch-0 root',
    wallet: 'account',
    request: moduleRequest('key', 'write', A2_ID, { path: PATHS.secondSign, ep: 0 }),
    expected: { ciphertext: hex(secondKid0.publicKey) },
    intermediate: intermediates(secondKid0),
    differsFrom: 'key-second-account-record'
  })
  const epochMessage = utf8(signingInput(hex(secondKid0.publicKey), 'LAB_SELF_TEST_ONLY VC-P256 epoch-0 payload'))
  const epochSignature = es256(secondKid0.d, epochMessage)
  add({
    id: 'sign-second-account-epoch-0', requirement: 'P256-01', kind: 'module',
    title: '`sign` with `ep` 0 signs with the epoch-0 child key, as the outgoing root\'s signature on a rotation record needs once epoch 1 is open (KEYS §1.10.2, "Dual signature")',
    wallet: 'account',
    request: moduleRequest('sign', 'write', A2_ID, { path: PATHS.secondSign, msg: epochMessage, ep: 0 }),
    expected: { ciphertext: hex(epochSignature.signature) },
    intermediate: { ...intermediates(secondKid0), digest: hex(sha256(epochMessage)), rfc6979: hex(epochSignature.raw), normalised: epochSignature.normalised }
  })

  // Recipient kids (ENV §8.6) and counterparty symmetry (KEYS §1.12).
  for (const [suffix, kidPath, title] of [['record', PATHS.encrypt, 'outer recipient'], ['field', PATHS.field, 'per-field recipient']]) {
    const writerSide = theirs(A.p256Seed, B.p256PublicKey, kidPath)
    const recipientSide = own(B.p256Seed, A.p256PublicKey, kidPath)
    same(writerSide.publicKey, recipientSide.publicKey, `symmetry ${suffix}`)
    add({
      id: `peer-recipient-${suffix}-kid`, requirement: 'P256-01', kind: 'module',
      title: `\`peer\`: the writer derives the ${title} kid of a P-256 recipient (ENV §8.6)`,
      wallet: 'account',
      request: moduleRequest('peer', 'write', A_ID, { path: kidPath, peer: B.p256PublicKey }),
      expected: { ciphertext: hex(writerSide.publicKey) },
      intermediate: intermediates(writerSide)
    })
    add({
      id: `key-recipient-${suffix}-kid`, requirement: 'P256-01', kind: 'module',
      title: `\`key\`: the recipient, under its own account tag, derives the same ${title} kid from its own root and the writer's root (counterparty symmetry)`,
      wallet: 'recipient',
      request: moduleRequest('key', 'read', B_ID, { path: kidPath, peer: A.p256PublicKey }),
      expected: { ciphertext: hex(recipientSide.publicKey) },
      intermediate: intermediates(recipientSide),
      sameAs: `peer-recipient-${suffix}-kid`
    })
  }
  const selfRecipient = own(A.p256Seed, A.p256PublicKey, PATHS.encrypt)
  add({
    id: 'key-self-recipient-record-kid', requirement: 'P256-01', kind: 'module',
    title: '`key`: the writer\'s self-recipient kid, distinct from its signing kid because the namespace differs (ENV §8.6)',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: PATHS.encrypt }),
    expected: { ciphertext: hex(selfRecipient.publicKey) },
    intermediate: intermediates(selfRecipient)
  })

  // The actor wallet: its persistent key (2-sdx delegate-actor/<index>, counterparty self), which
  // lies outside the runtime tree (KEYS §2.14.1), and a session key (KEYS §2.14.2).
  add({
    id: 'key-actor-root', requirement: 'P256-01', kind: 'module',
    title: '`key` without `path` and role `actor`: the actor root\'s public key. The tag names the account the actor acts for and selects nothing',
    wallet: 'actor',
    request: moduleRequest('key', 'actor', A_ID, {}),
    expected: { ciphertext: hex(C.p256PublicKey) }
  })
  const persistent = own(C.p256Seed, C.p256PublicKey, PATHS.actor(0))
  add({
    id: 'key-actor-persistent-0', requirement: 'P256-01', kind: 'module',
    title: '`key`: the actor wallet\'s persistent P-256 key at index 0, `2-sdx delegate-actor/0`, counterparty self, from the actor root; it is published in the actor\'s DID document and pinned raw in grants (KEYS §2.3, §2.14.1)',
    wallet: 'actor',
    request: moduleRequest('key', 'actor', A_ID, { path: PATHS.actor(0) }),
    expected: { ciphertext: hex(persistent.publicKey) },
    intermediate: intermediates(persistent)
  })
  const actorMessage = utf8(signingInput(hex(persistent.publicKey), 'LAB_SELF_TEST_ONLY VC-P256 actor payload'))
  const actorSignature = es256(persistent.d, actorMessage)
  add({
    id: 'sign-actor-persistent-0', requirement: 'P256-01', kind: 'module',
    title: '`sign` with role `actor`: an ES256 signature by the persistent key, the raw key a grant pins and a delegate record names in `kid` (KEYS §2.7.2, §2.14.1)',
    wallet: 'actor',
    request: moduleRequest('sign', 'actor', A_ID, { path: PATHS.actor(0), msg: actorMessage }),
    expected: { ciphertext: hex(actorSignature.signature) },
    intermediate: { ...intermediates(persistent), digest: hex(sha256(actorMessage)), rfc6979: hex(actorSignature.raw), normalised: actorSignature.normalised }
  })
  const sessionP256 = own(D.p256Seed, D.p256PublicKey, PATHS.session)
  add({
    id: 'key-session-p256', requirement: 'P256-01', kind: 'module',
    title: '`key` with role `session`: the session root named by the path\'s sessionId, self-derived under `sdx delegate` at the session key path (KEYS §1.6.1, §2.14.2); the same wallet\'s actor root is not used',
    wallet: 'actor',
    request: moduleRequest('key', 'session', A_ID, { path: PATHS.session }),
    expected: { ciphertext: hex(sessionP256.publicKey) },
    intermediate: intermediates(sessionP256)
  })
  const sessionMessage = utf8(signingInput(hex(sessionP256.publicKey), 'LAB_SELF_TEST_ONLY VC-P256 session payload'))
  const sessionSignature = es256(sessionP256.d, sessionMessage)
  add({
    id: 'sign-session', requirement: 'P256-01', kind: 'module',
    title: '`sign` with role `session`: the session actor signs a record with its session key (KEYS §2.14.2 step 5)',
    wallet: 'actor',
    request: moduleRequest('sign', 'session', A_ID, { path: PATHS.session, msg: sessionMessage }),
    expected: { ciphertext: hex(sessionSignature.signature) },
    intermediate: { ...intermediates(sessionP256), digest: hex(sha256(sessionMessage)), rfc6979: hex(sessionSignature.raw), normalised: sessionSignature.normalised }
  })
  const longKeyPath = identifier(NAMESPACES.sign, `${SCOPE}/${KEYWORDS.action}/`.padEnd(1033, '0'))
  const long = own(A.p256Seed, A.p256PublicKey, longKeyPath)
  if (Buffer.byteLength(splitIdentifier(longKeyPath).keyPath) !== 1033) fail('1033-byte key path')
  add({
    id: 'key-path-1033-bytes', requirement: 'P256-01', kind: 'module',
    title: '`key` accepts a key path of 1,033 bytes, the KEYS §1.3 ceiling',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: longKeyPath }),
    expected: { ciphertext: hex(long.publicKey) },
    intermediate: intermediates(long)
  })

  // A real offset >= n, found by the path grind.
  const rejected = offset(A.p256Seed, A.p256PublicKey, GRIND.path.identifier)
  add({
    id: 'key-offset-rejected', requirement: 'P256-01', kind: 'module',
    title: '`key` fails for a path whose HMAC is >= n; the value is not reduced mod n (KEYS §1.8.2)',
    wallet: 'account',
    request: moduleRequest('key', 'write', A_ID, { path: GRIND.path.identifier }),
    expected: { error: 'scalar-rejected' },
    intermediate: intermediates(rejected),
    found: 'grind path: identifier = prefix || 16 Crockford base32 digits of counter; see generator.grind.path'
  })
  add({
    id: 'sign-offset-rejected', requirement: 'P256-01', kind: 'module',
    title: '`sign` fails for the same path, before any signature is produced',
    wallet: 'account',
    request: moduleRequest('sign', 'write', A_ID, { path: GRIND.path.identifier, msg: utf8('LAB_SELF_TEST_ONLY') }),
    expected: { error: 'scalar-rejected' },
    intermediate: intermediates(rejected)
  })
  const notRejected = theirs(A.p256Seed, B.p256PublicKey, GRIND.path.identifier)
  add({
    id: 'peer-same-path-other-pair', requirement: 'P256-01', kind: 'module',
    title: 'The same path against another counterparty has a different HMAC key and derives normally',
    wallet: 'account',
    request: moduleRequest('peer', 'write', A_ID, { path: GRIND.path.identifier, peer: B.p256PublicKey }),
    expected: { ciphertext: hex(notRejected.publicKey) },
    intermediate: intermediates(notRejected)
  })

  // ES256: RFC 6979 nonce checks, then module signatures (low-S, KEYS §1.8.3).
  const rfcKey = 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721n
  const rfc = {
    sample: { k: 'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60', r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716', s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8' },
    test: { k: 'd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0', r: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367', s: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083' }
  }
  for (const [message, value] of Object.entries(rfc)) {
    const { signature, raw, normalised } = es256(rfcKey, utf8(message))
    if (hex(raw) !== value.r + value.s) fail(`RFC 6979 A.2.5 ${message}`)
    add({
      id: `es256-rfc6979-a25-${message}`, requirement: 'P256-01', kind: 'es256-external',
      title: `RFC 6979 Appendix A.2.5 (P-256, SHA-256), message "${message}": the RFC's nonce and (r, s), and the low-S form \`sign\` returns`,
      citation: { path: 'https://www.rfc-editor.org/rfc/rfc6979', clause: 'Appendix A.2.5' },
      privateKey: hex(be32(rfcKey)),
      publicKey: hex(p256.getPublicKey(be32(rfcKey), true)),
      message: hex(utf8(message)),
      expected: { k: value.k, rfc6979: value.r + value.s, signature: hex(signature), normalised }
    })
  }
  const kidHex = hex(kid.publicKey)
  const picks = {}
  for (let i = 0; !(picks.normalised && picks.unchanged); i++) {
    const message = signingInput(kidHex, `LAB_SELF_TEST_ONLY VC-P256 payload ${i}`)
    const result = es256(kid.d, utf8(message))
    const slot = result.normalised ? 'normalised' : 'unchanged'
    if (!picks[slot]) picks[slot] = { message, ...result }
  }
  for (const [slot, title] of [['normalised', 'the RFC 6979 s is above n/2 and is returned as n - s'], ['unchanged', 'the RFC 6979 s is already at most n/2 and is returned unchanged']]) {
    const { message, signature, raw, normalised } = picks[slot]
    add({
      id: `sign-record-${slot}`, requirement: 'P256-01', kind: 'module',
      title: `\`sign\`: ES256 over an ENV §8.2 signing input with the record signing key; ${title}`,
      wallet: 'account',
      request: moduleRequest('sign', 'write', A_ID, { path: PATHS.sign, msg: utf8(message) }),
      expected: { ciphertext: hex(signature) },
      intermediate: { ...intermediates(kid), digest: hex(sha256(utf8(message))), rfc6979: hex(raw), normalised }
    })
  }

  // decrypt: the JWE decryption step of ENV §5.3 and §14, run by the wallet's JOSE implementation
  // (ENV §16) with the one candidate key that `path` and `peer` select.
  const recordKid = own(A.p256Seed, A.p256PublicKey, PATHS.encrypt)
  const recipientRecordKid = own(B.p256Seed, A.p256PublicKey, PATHS.encrypt)
  const selfFieldKid = own(A.p256Seed, A.p256PublicKey, PATHS.field)
  const recipientFieldKid = own(B.p256Seed, A.p256PublicKey, PATHS.field)
  const writer = d => ({ kid: d.publicKey, d: d.d })
  const outerHeader = { enc: 'A256GCM', proto: FORMAT_IDENTIFIER, aid: IDS.recordId }
  const auditLayer = utf8(`LAB_SELF_TEST_ONLY VC-P256 audit layer of record ${IDS.recordId}`)
  const fieldPlaintext = utf8(`LAB_SELF_TEST_ONLY VC-P256 field ${IDS.fieldName} of record ${IDS.recordId}`)
  const outerSelf = await frozenJwe(frozen, 'outer-self', outerHeader, [writer(recordKid)], auditLayer)
  const outerTwo = await frozenJwe(frozen, 'outer-two', outerHeader, [writer(recordKid), writer(recipientRecordKid)], auditLayer)
  const fieldTwo = await frozenJwe(frozen, 'field-two', { enc: 'A256GCM' }, [writer(selfFieldKid), writer(recipientFieldKid)], fieldPlaintext)
  const decryptCase = (id, title, walletName, acct, fields, derived, opened, plaintext, frozenName, extra = {}) => add({
    id, requirement: 'P256-01', kind: 'module', title,
    wallet: walletName,
    request: moduleRequest('decrypt', 'read', acct, fields),
    expected: { plaintext: hex(plaintext) },
    intermediate: { ...intermediates(derived), z: hex(opened.z), kek: hex(opened.kek), cek: hex(opened.cek) },
    frozen: frozenName,
    ...extra
  })
  decryptCase('decrypt-outer-self', 'The writer opens its self-recipient entry of a one-recipient outer wrap: `proto` and `aid` in the protected header (ENV §5.2, §5.3), and `epk` there too, where jose writes it for one recipient', 'account', A_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: outerSelf.opened[0].entry }, recordKid, outerSelf.opened[0], auditLayer, 'outer-self')
  decryptCase('decrypt-outer-writer-entry', 'The writer opens its own entry of a two-recipient outer wrap, where each entry carries its own `epk` (ENV §5.2)', 'account', A_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: outerTwo.opened[0].entry }, recordKid, outerTwo.opened[0], auditLayer, 'outer-two')
  decryptCase('decrypt-outer-recipient-entry', 'The recipient, under its own account tag, opens its entry of the same outer wrap with the writer\'s root as `peer` (ENV §8.6)', 'recipient', B_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: outerTwo.opened[1].entry }, recipientRecordKid, outerTwo.opened[1], auditLayer, 'outer-two')
  decryptCase('decrypt-field-recipient-entry', 'The recipient opens its entry of a per-field JWE with two recipients, the writer first (ENV §8.6, §9); the key path ends `/field/<fieldName>`', 'recipient', B_ID,
    { path: PATHS.field, peer: A.p256PublicKey, jwe: fieldTwo.opened[1].entry }, recipientFieldKid, fieldTwo.opened[1], fieldPlaintext, 'field-two')
  const decryptFails = (id, title, walletName, acct, fields, derived, entry, frozenName) => {
    add({
      id, requirement: 'P256-01', kind: 'module', title,
      wallet: walletName,
      request: moduleRequest('decrypt', 'read', acct, fields),
      expected: { error: 'decrypt-failed' },
      intermediate: { ...intermediates(derived), ...(entry ? Object.fromEntries(Object.entries(failedEntry(entry, derived.d)).map(([k, v]) => [k, hex(v)])) : {}) },
      frozen: frozenName
    })
  }
  const recipientOuter = outerTwo.opened[1].entry
  decryptFails('decrypt-wrong-path', 'The recipient\'s field entry with the record\'s key path: another candidate key, so the AES key unwrap fails its integrity check', 'recipient', B_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: fieldTwo.opened[1].entry }, recipientRecordKid, fieldTwo.opened[1].entry, 'field-two')
  decryptFails('decrypt-other-entry', 'The recipient presents the writer\'s entry of the outer wrap: its one candidate key does not open it', 'recipient', B_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: outerTwo.opened[0].entry }, recipientRecordKid, outerTwo.opened[0].entry, 'outer-two')
  const flipLast = text => { const bytes = Buffer.from(text, 'base64url'); bytes[bytes.length - 1] ^= 1; return b64u(bytes) }
  decryptFails('decrypt-tampered-ciphertext', 'One altered ciphertext byte: the content-encryption key unwraps, and AES-GCM authentication fails', 'recipient', B_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: { ...recipientOuter, ciphertext: flipLast(recipientOuter.ciphertext) } }, recipientRecordKid, null, 'outer-two')
  const otherAid = b64u(utf8(JSON.stringify({ ...JSON.parse(Buffer.from(recipientOuter.protected, 'base64url')), aid: IDS.secondRecordId })))
  decryptFails('decrypt-protected-aid-altered', 'The protected header with another `aid`: it is the AES-GCM additional data, so decryption fails rather than being misdirected (ENV §5.3)', 'recipient', B_ID,
    { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: { ...recipientOuter, protected: otherAid } }, recipientRecordKid, null, 'outer-two')
  decryptContext.outer = { entry: recipientOuter, selfEntry: outerSelf.opened[0].entry, field: fieldTwo.opened[1].entry }

  pointRejections(add)
  requestRejections(add)
  behaviours(add)
  return {
    schema: 'tpnil-sdx-vectors@0.1.0',
    suite: 'VC-P256',
    claim: 'LAB_SELF_TEST_ONLY',
    status: 'PROPOSED',
    title: 'SDX accounts in a BRC-98 module (`p sdx`), P-256 operations: roots, account selection, derivation, signatures, JWE decryption and rejections',
    requirements: ['P256-01', 'P256-02', 'P256-03', 'P256-04'],
    citations: [
      { path: DRAFT, clause: 'Roots and selection' },
      { path: DRAFT, clause: 'Canonical derivation: one root for both curves' },
      { path: DRAFT, clause: 'Scheme, operations and carrier methods' },
      { path: DRAFT, clause: 'Point validation' },
      { path: DRAFT, clause: 'Permissions' },
      { path: DRAFT, clause: 'Path scoping' },
      { path: DRAFT, clause: 'Containment' },
      { path: PROGRAM, clause: 'requirements P256-01, P256-02, P256-03, P256-04' },
      { path: KEYS, clause: '§1.3' },
      { path: KEYS, clause: '§1.3.1' },
      { path: KEYS, clause: '§1.4.2' },
      { path: KEYS, clause: '§1.4.3' },
      { path: KEYS, clause: '§1.6.1' },
      { path: KEYS, clause: '§1.7' },
      { path: KEYS, clause: '§1.8.1' },
      { path: KEYS, clause: '§1.8.2' },
      { path: KEYS, clause: '§1.8.3' },
      { path: KEYS, clause: '§1.10.2' },
      { path: KEYS, clause: '§1.11.2' },
      { path: KEYS, clause: '§1.12' },
      { path: KEYS, clause: '§2.14.1' },
      { path: KEYS, clause: '§2.14.2' },
      { path: ENV, clause: '§2.1' },
      { path: ENV, clause: '§5.2' },
      { path: ENV, clause: '§5.3' },
      { path: ENV, clause: '§8.2' },
      { path: ENV, clause: '§8.5' },
      { path: ENV, clause: '§8.6' },
      { path: ENV, clause: '§9' },
      { path: ENV, clause: '§14' },
      { path: ENV, clause: '§16' },
      { path: 'https://www.rfc-editor.org/rfc/rfc6979', clause: 'Appendix A.2.5' },
      { path: 'https://www.rfc-editor.org/rfc/rfc7516', clause: '§7.2' },
      { path: 'https://www.rfc-editor.org/rfc/rfc7518', clause: '§4.6' },
      brc(42, 'Specification'),
      brc(43, 'Specification'),
      brc(98, 'Specification'),
      brc(229, 'Logical protocol ID; Point validation')
    ],
    decisions: DECISIONS.vc,
    profile: profile(),
    testKeys: testKeys([...ROOT_NAMES, 'unusable']),
    wallets: walletsTable(['account', 'recipient', 'actor']),
    generator: generator(),
    oracles: P256_ORACLES(),
    cases
  }
}

// Invalid point encodings on one curve, each with the reason a validator gives.
function invalidEncodings(curve, valid) {
  const C = curve === 'P-256' ? p256 : secp256k1
  const prime = curve === 'P-256' ? P : PK
  const { x: vx, y: vy } = C.Point.fromHex(hex(valid)).toAffine()
  const isX = x => { try { C.Point.fromHex('02' + x.toString(16).padStart(64, '0')); return true } catch { return false } }
  let firstValid = 0n
  while (!isX(firstValid)) firstValid++
  let firstInvalid = 0n
  while (isX(firstInvalid)) firstInvalid++
  const at = (prefix, x) => Uint8Array.from([prefix, ...be32(x)])
  const reduced = k => isX(k) ? `; a parser that reduces x mod p first would accept the valid point with x = ${k}` : ''
  const encodings = [
    ['x-all-ones', at(2, (1n << 256n) - 1n), 'point-x-range', 'x = 2^256 - 1, not less than p'],
    ['x-equals-p', at(2, prime), 'point-x-range', `x = p${reduced(0n)}`],
    ['x-equals-p-plus-1', at(2, prime + 1n), 'point-x-range', `x = p + 1${reduced(1n)}`],
    ...(firstValid > 1n ? [[`x-equals-p-plus-${firstValid}`, at(2, prime + firstValid), 'point-x-range', `x = p + ${firstValid}${reduced(firstValid)}`]] : []),
    ['x-not-on-curve-02', at(2, firstInvalid), 'point-not-on-curve', `x = ${firstInvalid}: the curve equation has no solution for y`],
    ['x-not-on-curve-03', at(3, firstInvalid), 'point-not-on-curve', `x = ${firstInvalid} with prefix 03`],
    ['prefix-00', at(0, vx), 'point-prefix', '33 bytes with prefix 00'],
    ['prefix-01', at(1, vx), 'point-prefix', '33 bytes with prefix 01'],
    ['prefix-04-33-bytes', at(4, vx), 'point-prefix', '33 bytes with the uncompressed prefix 04'],
    ['uncompressed-65-bytes', Uint8Array.from([4, ...be32(vx), ...be32(vy)]), 'point-length', 'the valid point, SEC1 uncompressed'],
    ['x-only-32-bytes', be32(vx), 'point-length', 'the bare x-coordinate'],
    ['trailing-byte-34-bytes', Uint8Array.from([...valid, 0]), 'point-length', 'the valid point followed by 00'],
    ['sec1-infinity', Uint8Array.from([0]), 'point-length', 'the SEC1 encoding of the point at infinity'],
    ['empty', new Uint8Array(0), 'point-length', 'zero bytes']
  ]
  return encodings.map(([name, encoding, error, description]) => {
    const x = encoding.length === 33 ? toBig(encoding.subarray(1)) : null
    return { name, encoding, error, description, ...(x !== null && x >= prime ? { reducesTo: { x: hex(be32(x % prime)), validX: isX(x % prime) } } : {}) }
  })
}

// P256-02: each invalid encoding in every P-256 point position. `decrypt`'s ephemeral key is a JWK
// inside `jwe`, so its rejections are the request cases decrypt-epk-*.
function pointRejections(add) {
  const msg = utf8('LAB_SELF_TEST_ONLY')
  for (const { name, encoding, error, description, reducesTo } of invalidEncodings('P-256', B.p256PublicKey)) {
    const positions = [
      ['key', 'peer', moduleRequest('key', 'write', A_ID, { path: PATHS.sign, peer: encoding })],
      ['peer', 'peer', moduleRequest('peer', 'write', A_ID, { path: PATHS.encrypt, peer: encoding })],
      ['sign', 'peer', moduleRequest('sign', 'write', A_ID, { path: PATHS.sign, peer: encoding, msg })],
      ['decrypt', 'peer', moduleRequest('decrypt', 'read', A_ID, { path: PATHS.encrypt, peer: encoding, jwe: decryptContext.outer.selfEntry })]
    ]
    add({
      id: `point-${name}`, requirement: 'P256-02', kind: 'point-rejection',
      title: `Rejected before multiplication: ${description}`,
      wallet: 'account',
      curve: 'P-256',
      encoding: hex(encoding),
      ...(reducesTo ? { reducesTo } : {}),
      requests: positions.map(([operation, field, req]) => ({ operation, field, ...req })),
      expected: { error }
    })
  }
}

// P256-03: carriers, other methods, reserved names, counterparty, security level, privileged,
// operation and logical protocol ID grammar, the namespace and key-path rules, path scope, root
// selection, the CBOR inputs and the shape of `decrypt`'s JWE.
function requestRejections(add) {
  const msg = utf8('LAB_SELF_TEST_ONLY')
  const tagA = TAGS[A_ID]
  const { entry, field } = decryptContext.outer
  const inputs = {
    key: { path: PATHS.sign },
    peer: { path: PATHS.encrypt, peer: B.p256PublicKey },
    sign: { path: PATHS.sign, msg },
    decrypt: { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: entry },
    open: { acct: A_ID }
  }
  const reject = (id, scope, title, req, error, wallet = 'account') => add({ id, requirement: 'P256-03', kind: 'request-rejection', scope, title, wallet, request: req, expected: { error } })
  reject('encrypt-with-decrypt', 'carrier', '`encrypt` carrying `decrypt`: only `decrypt` travels on `decrypt`', request('encrypt', protocolNameOf('decrypt', 'read', B_ID), inputs.decrypt), 'wrong-carrier', 'recipient')
  for (const [operation, role] of [['key', 'write'], ['peer', 'write'], ['sign', 'write'], ['open', 'root']]) {
    reject(`decrypt-with-${operation}`, 'carrier', `\`decrypt\` carrying \`${operation}\``, request('decrypt', protocolNameOf(operation, role, A_ID), inputs[operation]), 'wrong-carrier')
  }
  const protocolID = [2, protocolNameOf('key', 'write', A_ID)]
  const others = [
    ['getPublicKey', { protocolID, keyID: '1', counterparty: 'self' }],
    ['createSignature', { protocolID, keyID: '1', counterparty: 'self', data: hex(msg) }],
    ['verifySignature', { protocolID, keyID: '1', counterparty: 'self', data: hex(msg), signature: '3006020101020101' }],
    ['createHmac', { protocolID, keyID: '1', counterparty: 'self', data: hex(msg) }],
    ['verifyHmac', { protocolID, keyID: '1', counterparty: 'self', data: hex(msg), hmac: '00'.repeat(32) }],
    ['revealSpecificKeyLinkage', { protocolID, keyID: '1', counterparty: hex(B.secp256k1PublicKey), verifier: hex(B.secp256k1PublicKey) }]
  ]
  for (const [method, args] of others) reject(`method-${method}`, 'method', `\`${method}\` under \`p sdx\``, { method, args }, 'method-not-permitted')
  const names = [
    ['createAction-basket', 'createAction', { description: 'LAB_SELF_TEST_ONLY action', outputs: [{ lockingScript: '6a', satoshis: 0, basket: 'p sdx lab basket', outputDescription: 'lab output' }] }],
    ['createAction-label', 'createAction', { description: 'LAB_SELF_TEST_ONLY action', outputs: [{ lockingScript: '6a', satoshis: 0, outputDescription: 'lab output' }], labels: ['p sdx lab label'] }],
    ['listOutputs-basket', 'listOutputs', { basket: 'p sdx lab basket' }],
    ['listActions-label', 'listActions', { labels: ['p sdx lab label'] }],
    ['relinquishOutput-basket', 'relinquishOutput', { basket: 'p sdx lab basket', output: '00'.repeat(32) + '.0' }]
  ]
  for (const [id, method, args] of names) reject(`reserved-${id}`, 'names', `A \`p sdx\` basket or label in \`${method}\``, { method, args }, 'reserved-namespace')
  const keyName = protocolNameOf('key', 'write', A_ID)
  reject('counterparty-anyone', 'counterparty', '`counterparty` other than `self`: `anyone`', request('encrypt', keyName, inputs.key, { counterparty: 'anyone' }), 'counterparty-not-self')
  reject('counterparty-public-key', 'counterparty', '`counterparty` other than `self`: a secp256k1 public key', request('encrypt', keyName, inputs.key, { counterparty: hex(B.secp256k1PublicKey) }), 'counterparty-not-self')
  for (const level of [0, 1]) {
    const req = request('encrypt', keyName, inputs.key)
    req.args.protocolID[0] = level
    reject(`security-level-${level}`, 'grant', `Security level ${level}: the module accepts only level 2`, req, 'security-level')
  }
  reject('privileged-request', 'grant', '`privileged: true`: no account has a privileged root', request('encrypt', keyName, inputs.key, { privileged: true, privilegedReason: 'LAB_SELF_TEST_ONLY' }), 'privileged-not-supported')

  // Namespaces: registered for the curve, the rotation namespace reserved, and separation both ways.
  const record = KEY_PATHS.record
  reject('sign-encryption-namespace', 'path', '`sign` for a path in the encryption namespace: a key derived for encryption never signs (KEYS §1.7, §1.11.2)', moduleRequest('sign', 'write', A_ID, { path: PATHS.encrypt, msg }), 'namespace-encryption')
  reject('decrypt-signing-namespace', 'path', '`decrypt` for a path in the signing namespace: a key derived for signing never decrypts (KEYS §1.7, §1.11.2)', moduleRequest('decrypt', 'read', A_ID, { ...inputs.decrypt, path: PATHS.sign }), 'namespace-decrypt')
  reject('decrypt-delegation-namespace', 'path', '`decrypt` for a path in the delegation namespace', moduleRequest('decrypt', 'read', A_ID, { ...inputs.decrypt, path: identifier(NAMESPACES.delegate, record) }), 'namespace-decrypt')
  reject('key-namespace-rotation', 'path', '`key` under `sdx rotation`, which SDX reserves: rotation records sign under the signing namespace (KEYS §1.7, §1.10.3)', moduleRequest('key', 'write', A_ID, { path: identifier(NAMESPACES.rotation, record) }), 'namespace-rotation')
  reject('sign-namespace-rotation', 'path', '`sign` under `sdx rotation`', moduleRequest('sign', 'root', A_ID, { path: identifier(NAMESPACES.rotation, record), msg }), 'namespace-rotation')
  reject('key-namespace-wrong-curve', 'path', '`key` for a path in `sdx handoff`, which the profile registers on secp256k1 only (KEYS §1.7)', moduleRequest('key', 'write', A_ID, { path: PATHS.handoff }), 'namespace-curve')
  reject('key-namespace-unregistered', 'path', '`key` for a path in a namespace the profile does not register (KEYS §1.7)', moduleRequest('key', 'write', A_ID, { path: identifier('sdx bogus', record) }), 'namespace-unregistered')
  reject('key-path-security-level-1', 'path', '`key` for a derivation identifier at security level 1: namespaces are used at level 2 (KEYS §1.7)', moduleRequest('key', 'write', A_ID, { path: `1-${NAMESPACES.sign}-${record}` }), 'path-identifier')
  reject('key-path-not-identifier', 'path', '`key` for a bare key path with no security level or namespace', moduleRequest('key', 'write', A_ID, { path: record }), 'path-identifier')
  // Key paths (KEYS §1.3, §1.6.1, §1.12 item 10, §2.14.1).
  reject('key-purpose-unregistered', 'path', '`key` for a level-4 purpose the profile does not register: rejected at the derivation boundary (KEYS §1.6.1, §1.12 item 10)', moduleRequest('key', 'write', A_ID, { path: identifier(NAMESPACES.encrypt, `${record}/photo/${IDS.fieldName}`) }), 'purpose-unregistered')
  reject('key-path-record-keyword', 'path', '`key` with the level-3 keyword `record`, ENV §8.5\'s example literal: the laboratory profile spells it `action` (decision D-PROFILE)', moduleRequest('key', 'write', A_ID, { path: identifier(NAMESPACES.sign, `${SCOPE}/record/${IDS.recordId}`) }), 'key-path-grammar')
  reject('key-path-level-3-incomplete', 'path', '`key` for `.../action` with no action identifier', moduleRequest('key', 'write', A_ID, { path: identifier(NAMESPACES.sign, `${SCOPE}/${KEYWORDS.action}`) }), 'key-path-grammar')
  reject('key-path-session-level-4', 'path', '`key` for a level-4 segment under `session`: only `action` has a level 4', moduleRequest('key', 'session', A_ID, { path: `${PATHS.session}/field/${IDS.fieldName}` }), 'key-path-grammar', 'actor')
  reject('key-path-delegation-variant', 'path', '`key` for the KEYS §1.6.1 delegation variant: its actor-side key is the grant\'s pinned key, not a root the module holds, and KEYS §2.14.1 keeps it off the dispatch path', moduleRequest('key', 'write', A_ID, { path: delegationPath(hex(C.p256PublicKey)) }), 'key-path-grammar')
  reject('key-path-actor-under-account-role', 'path', '`key` with role `write` for `actor/0`: the actor\'s persistent key belongs to an actor root, outside any account tree', moduleRequest('key', 'write', A_ID, { path: PATHS.actor(0) }), 'key-path-grammar')
  reject('key-path-account-under-actor-role', 'path', '`key` with role `actor` for an account key path: role actor derives only `actor/<index>` (KEYS §2.14.1)', moduleRequest('key', 'actor', A_ID, { path: identifier(NAMESPACES.delegate, record) }), 'key-path-grammar', 'actor')
  reject('key-path-actor-index-leading-zero', 'path', '`key` with role `actor` for `actor/01`: the index is a decimal number with no leading zero', moduleRequest('key', 'actor', A_ID, { path: PATHS.actor('01') }), 'key-path-grammar', 'actor')
  const path1034 = identifier(NAMESPACES.sign, `${SCOPE}/${KEYWORDS.action}/`.padEnd(1034, '0'))
  reject('key-path-1034-bytes', 'path', '`key` for a key path of 1,034 bytes, over the KEYS §1.3 ceiling', moduleRequest('key', 'write', A_ID, { path: path1034 }), 'key-path-length')

  // Grants: path prefixes, operations and accounts are scoped separately.
  reject('path-outside-grant-namespace', 'grant', '`sign` for a path under `sdx delegate`, which the `sign` grant does not cover', moduleRequest('sign', 'write', A_ID, { path: identifier(NAMESPACES.delegate, record), msg }), 'path-not-granted')
  const otherAccount = identifier(NAMESPACES.sign, actionOf(`${KEYWORDS.account}/${A_ID}X/${KEYWORDS.runtime}/${IDS.runtimeId}`, IDS.recordId))
  reject('path-outside-grant-account', 'grant', '`sign` for another account whose ID extends the granted one; the prefix ends at a "/"', moduleRequest('sign', 'write', A_ID, { path: otherAccount, msg }), 'path-not-granted')
  reject('no-grant-for-operation', 'grant', '`peer` with role `read`, where only `key` with role `read` is granted: each operation is granted separately', moduleRequest('peer', 'read', A_ID, { path: PATHS.encrypt, peer: B.p256PublicKey }), 'no-grant')
  reject('account-isolation', 'grant', `\`peer\` for ${A2_ID}, where \`peer\` is granted only for ${A_ID}: a grant for one account never covers another`, moduleRequest('peer', 'write', A2_ID, { path: PATHS.secondSign, peer: B.p256PublicKey }), 'no-grant')
  // Authorization comes before anything the wallet holds is read (Permissions), so a caller with no
  // grant gets the same refusal whether or not the wallet holds the account or the epoch.
  reject('no-grant-unheld-account', 'grant', `\`key\` with role \`read\` for ${NEW_ID}, an account the wallet does not hold, with no grant for it: refused as not granted, so the refusal does not show whether the wallet holds the account`, moduleRequest('key', 'read', NEW_ID, {}), 'no-grant')
  reject('no-grant-unheld-epoch', 'grant', `\`key\` with role \`read\` for ${A2_ID} at \`ep\` 2, an epoch the wallet does not hold, with no grant for it: refused as not granted`, moduleRequest('key', 'read', A2_ID, { ep: 2 }), 'no-grant')
  reject('unknown-operation', 'operation', 'An operation the scheme does not define (`verify`) on `encrypt`', request('encrypt', `${SCHEME} verify write ${tagA}`, inputs.key), 'unknown-operation')
  reject('removed-operation-unwrap', 'operation', '`unwrap`, which `decrypt` replaced (ENV §16), on `decrypt`', request('decrypt', `${SCHEME} unwrap read ${tagA}`, { path: PATHS.encrypt, peer: A.p256PublicKey }), 'unknown-operation')
  reject('removed-operation-link', 'operation', '`link`, which this module does not define: SDX v0.1 leaves third-party verification out of scope (ENV §8.5)', request('encrypt', `${SCHEME} link write ${tagA}`, inputs.key), 'unknown-operation')
  for (const [id, name, title] of [
    ['logical-unknown-role', `${SCHEME} key admin ${tagA}`, 'a role the scheme does not define (`admin`)'],
    ['logical-uppercase-role', `${SCHEME} key Write ${tagA}`, 'an uppercase role'],
    ['logical-tag-31-hex', `${SCHEME} key write ${tagA.slice(0, 31)}`, 'a tag of 31 hex characters'],
    ['logical-tag-33-hex', `${SCHEME} key write ${tagA}0`, 'a tag of 33 hex characters'],
    ['logical-tag-uppercase', `${SCHEME} key write ${tagA.toUpperCase()}`, 'an uppercase hex tag'],
    ['logical-base58-account', `${SCHEME} key write ${A_ID}`, 'the base58 account ID in place of its tag'],
    ['logical-missing-tag', `${SCHEME} key write`, 'no tag'],
    ['logical-extra-token', `${SCHEME} key write ${tagA} x`, 'a token after the tag'],
    ['logical-repeated-space', `${SCHEME} key write  ${tagA}`, 'a repeated space'],
    ['logical-trailing-space', `${SCHEME} key write ${tagA} `, 'a trailing space'],
    ['logical-previous-form', `${SCHEME} key sdx write ${tagA}`, 'the form `sdx <role> <h>` of the earlier `p p256` draft']
  ]) reject(id, 'logical-protocol-id', `Logical protocol ID with ${title}`, request('encrypt', name, inputs.key), 'logical-protocol-id')

  // Root selection (Roots and selection).
  reject('unknown-account', 'selection', `A tag that names no account the wallet holds (${NEW_ID}), although a standing grant names it`, moduleRequest('key', 'write', NEW_ID, {}), 'unknown-account')
  reject('unknown-epoch', 'selection', `\`ep\` 2, which ${A2_ID} does not have`, moduleRequest('key', 'write', A2_ID, { ep: 2 }), 'unknown-epoch')
  reject('unknown-epoch-imported', 'selection', `\`ep\` 1 for ${A_ID}, which the wallet holds only at epoch 0; only \`open\` creates an epoch`, moduleRequest('key', 'write', A_ID, { ep: 1 }), 'unknown-epoch')
  reject('epoch-with-actor-role', 'selection', 'Role `actor` with `ep`: the actor root has no epochs', moduleRequest('key', 'actor', A_ID, { path: PATHS.actor(0), ep: 0 }), 'epoch-not-allowed', 'actor')
  reject('epoch-with-session-role', 'selection', 'Role `session` with `ep`', moduleRequest('key', 'session', A_ID, { path: PATHS.session, ep: 0 }), 'epoch-not-allowed', 'actor')
  reject('session-path-names-no-session', 'selection', 'Role `session` with a path that names no session, so no session root is selected', moduleRequest('key', 'session', A_ID, { path: identifier(NAMESPACES.delegate, record) }), 'session-not-selected', 'actor')
  reject('session-key-without-path', 'selection', 'Role `session` without `path`: only the path names the session', moduleRequest('key', 'session', A_ID, {}), 'session-not-selected', 'actor')
  reject('open-role-write', 'selection', '`open` with role `write`: `open` requires role `root`', moduleRequest('open', 'write', A_ID, inputs.open), 'open-role')
  reject('open-tag-mismatch', 'selection', `\`open\` whose tag is ${A_ID}'s while \`acct\` is ${A2_ID}`, request('encrypt', protocolNameOf('open', 'root', A_ID), { acct: A2_ID }), 'account-tag-mismatch')

  const input = (id, title, req, error, wallet) => reject(id, 'input', title, req, error, wallet)
  input('peer-without-peer', '`peer` without its required `peer` member', moduleRequest('peer', 'write', A_ID, { path: PATHS.encrypt }), 'missing-member')
  input('sign-without-msg', '`sign` without `msg`', moduleRequest('sign', 'write', A_ID, { path: PATHS.sign }), 'missing-member')
  input('sign-without-path', '`sign` without `path`; only `key` and `k1key` may omit it', moduleRequest('sign', 'write', A_ID, { msg }), 'missing-member')
  input('key-peer-without-path', '`key` with `peer` but no `path`: the root public key takes no counterparty', moduleRequest('key', 'write', A_ID, { peer: B.p256PublicKey }), 'missing-member')
  input('decrypt-without-jwe', '`decrypt` without `jwe`', moduleRequest('decrypt', 'read', A_ID, { path: PATHS.encrypt, peer: A.p256PublicKey }), 'missing-member')
  input('decrypt-without-peer', '`decrypt` without `peer`: the writer\'s root, or the reader\'s own for a self entry, is required', moduleRequest('decrypt', 'read', A_ID, { path: PATHS.encrypt, jwe: entry }), 'missing-member')
  input('decrypt-jwe-as-bytes', '`jwe` as a byte string instead of a map', moduleRequest('decrypt', 'read', A_ID, { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: utf8(JSON.stringify(entry)) }), 'member-type')
  input('open-without-acct', '`open` without `acct`', moduleRequest('open', 'root', A_ID, {}), 'missing-member')
  input('open-with-path', '`open` with a `path`, which it does not define', moduleRequest('open', 'root', A_ID, { acct: A_ID, path: PATHS.sign }), 'unknown-member')
  input('open-acct-as-bytes', '`acct` as a byte string instead of a text string', moduleRequest('open', 'root', A_ID, { acct: utf8(A_ID) }), 'member-type')
  input('path-as-bytes', '`path` as a byte string instead of a text string', moduleRequest('key', 'write', A_ID, { path: utf8(PATHS.sign) }), 'member-type')
  input('ep-as-text', '`ep` as a text string instead of an unsigned integer', moduleRequest('key', 'write', A2_ID, { ep: '0' }), 'member-type')
  input('ep-negative', '`ep` as a negative integer', moduleRequest('key', 'write', A2_ID, { ep: -1 }), 'member-type')
  input('ep-as-bytes', '`ep` as a byte string', moduleRequest('key', 'write', A2_ID, { ep: new Uint8Array([0]) }), 'member-type')
  input('unknown-member', 'An input member the operation does not define', moduleRequest('key', 'write', A_ID, { path: PATHS.sign, extra: new Uint8Array([0]) }), 'unknown-member')

  // decrypt's JWE: the shape SDX writes, and the ephemeral key validated as a P-256 point before any
  // ECDH (draft "Point validation"). The recipient wallet sends each one.
  const jweRequest = jwe => moduleRequest('decrypt', 'read', B_ID, { path: PATHS.encrypt, peer: A.p256PublicKey, jwe })
  const epk = entry.header.epk
  const withEpk = change => ({ ...entry, header: { ...entry.header, epk: { ...epk, ...change } } })
  const at = x => b64u(be32(x))
  let offCurve = 1n
  while ((() => { try { p256.Point.fromHex('02' + offCurve.toString(16).padStart(64, '0')); return true } catch { return false } })()) offCurve++
  const yFlipped = Buffer.from(epk.y, 'base64url'); yFlipped[31] ^= 1
  input('decrypt-epk-x-equals-p', '`epk` with x = p: rejected before any parser that reduces x', jweRequest(withEpk({ x: at(P) })), 'point-x-range', 'recipient')
  input('decrypt-epk-not-on-curve', `\`epk\` with x = ${offCurve}, for which P-256 has no y`, jweRequest(withEpk({ x: at(offCurve) })), 'point-not-on-curve', 'recipient')
  input('decrypt-epk-y-mismatch', '`epk` whose y is not the point\'s own y (its low bit flipped)', jweRequest(withEpk({ y: b64u(yFlipped) })), 'point-not-on-curve', 'recipient')
  input('decrypt-epk-other-curve', '`epk` naming another curve (`secp256k1`)', jweRequest(withEpk({ crv: 'secp256k1' })), 'jwe-shape', 'recipient')
  input('decrypt-alg-ecdh-es', 'An entry whose `alg` is `ECDH-ES`: every SDX identity recipient is `ECDH-ES+A256KW` (ENV §16)', jweRequest({ ...entry, header: { ...entry.header, alg: 'ECDH-ES' } }), 'jwe-shape', 'recipient')
  const selfProtected = JSON.parse(Buffer.from(decryptContext.outer.selfEntry.protected, 'base64url'))
  input('decrypt-member-in-both-headers', 'A one-recipient entry that repeats the protected header\'s `epk` in its own header (RFC 7516 §7.2.1)', moduleRequest('decrypt', 'read', A_ID, { path: PATHS.encrypt, peer: A.p256PublicKey, jwe: { ...decryptContext.outer.selfEntry, header: { ...decryptContext.outer.selfEntry.header, epk: selfProtected.epk } } }), 'jwe-shape')
  input('decrypt-unprotected-member', 'An entry with a shared `unprotected` header, which SDX does not write', jweRequest({ ...entry, unprotected: { zip: 'DEF' } }), 'jwe-shape', 'recipient')
  input('decrypt-without-tag', 'An entry without `tag`', jweRequest(Object.fromEntries(Object.entries(field).filter(([k]) => k !== 'tag'))), 'jwe-shape', 'recipient')

  const pathEntry = entryBytes({ path: PATHS.sign }), peerEntry = entryBytes({ peer: B.p256PublicKey })
  const rawCbor = (id, title, bytes, name = keyName) => {
    const req = { method: 'encrypt', args: { protocolID: [2, name], keyID: '1', counterparty: 'self', plaintext: hex(bytes) } }
    add({ id, requirement: 'P256-03', kind: 'request-rejection', scope: 'input', title, wallet: 'account', request: req, expected: { error: 'input-encoding' } })
  }
  rawCbor('cbor-unsorted-keys', 'Input map with `peer` before `path`: not the deterministic key order', Buffer.concat([Buffer.from([0xa2]), peerEntry, pathEntry]))
  rawCbor('cbor-non-shortest-length', 'Input map whose `path` key length is encoded in two bytes', Buffer.concat([Buffer.from([0xa1, 0x78, 0x04]), Buffer.from('path'), entryBytes({ path: PATHS.sign }).subarray(5)]))
  rawCbor('cbor-indefinite-map', 'Input as an indefinite-length map', Buffer.concat([Buffer.from([0xbf]), pathEntry, Buffer.from([0xff])]))
  rawCbor('cbor-duplicate-key', 'Input map with `path` twice', Buffer.concat([Buffer.from([0xa2]), pathEntry, pathEntry]))
  rawCbor('cbor-non-shortest-integer', 'Input map whose `ep` 1 is encoded in two bytes (0x18 0x01)', Buffer.concat([Buffer.from([0xa1, 0x62]), Buffer.from('ep'), Buffer.from([0x18, 0x01])]), protocolNameOf('key', 'write', A2_ID))
}

// P256-04: behavioural rows (no portable bytes).
function behaviours(add) {
  const sign = `[2, "${protocolNameOf('sign', 'write', A_ID)}"]`
  const rows = [
    ['seek-permission-false', `No grant exists for the originator and ${sign}.`, 'The application calls `encrypt` with `seekPermission: false`.', 'The call fails and no prompt is shown.', 'Permissions'],
    ['grant-records-prefixes', `No grant exists for ${sign}.`, 'The application calls `sign` and the user approves.', 'The prompt shows the derivation-identifier prefixes the grant will cover, and the grant records them; later requests outside them are refused (request vectors path-outside-grant-*).', 'Permissions'],
    ['operation-granted-separately', `A grant exists for [2, "${protocolNameOf('key', 'write', A_ID)}"].`, 'The application calls `sign` under the same logical protocol ID.', 'The `key` grant does not satisfy it; the operation is part of the protocol name.', 'Permissions'],
    ['account-isolation', `A grant exists for ${sign}.`, `The application calls \`sign\` with role \`write\` and the tag of another account the wallet holds (${A2_ID}).`, 'The grant does not satisfy it: the logical protocol ID names the account (request vector account-isolation).', 'Permissions'],
    ['grant-independence', `A grant exists for ordinary [2, "${logicalOf('write', A_ID)}"] (BRC-100 \`encrypt\`).`, `The application requests ${sign}.`, 'The ordinary grant does not satisfy the module request, and a module grant does not satisfy the ordinary protocol.', 'Permissions'],
    ['originator-scope', `A grant exists for originator \`a.example\` and ${sign}.`, 'Originator `b.example` makes the same request.', 'The grant does not satisfy it.', 'Permissions'],
    ['privileged-never-granted', 'Any wallet state.', 'A request arrives with `privileged: true`.', 'It is refused without a prompt and no grant is created (request vector privileged-request).', 'Path scoping'],
    ['open-prompts-on-create', `A standing grant exists for [2, "${protocolNameOf('open', 'root', A_ID)}"].`, 'The application calls `open` for an epoch of that account the wallet does not hold.', 'The wallet prompts, showing the account tag and the epoch and that the request creates a new epoch; no standing grant covers creation (cases open-creates-*).', 'Permissions'],
    ['sign-prompt-content', 'No grant exists.', 'The application calls `sign`.', 'The trusted UI shows the operation, the role, the account tag, `keyID`, `path`, and the message length and SHA-256 digest.', 'Permissions'],
    ['decrypt-prompt-content', 'No grant exists.', 'The application calls `decrypt`.', 'The trusted UI states that the application is decrypting data addressed to the account\'s P-256 key.', 'Permissions'],
    ['session-first-use', `The actor wallet holds no root for session ${'0'.repeat(32)}.`, `The application calls \`key\` with role \`session\` and a path naming that session.`, 'The wallet draws a fresh 64-byte root for the session on first use and discards it when the session ends; the result cannot be reproduced from any vector.', 'Roots and selection'],
    ['containment', 'Any request.', 'Any operation succeeds.', 'The result is a 33-byte public key, the 66-byte R || K of `open`, a 64-byte low-S signature, or the plaintext of a JWE entry; it is never `ikm`, `d`, a seed, a child private key, an ECDH secret or a content-encryption key.', 'Containment']
  ]
  for (const [id, given, when, then, clause] of rows) {
    add({ id: `behaviour-${id}`, requirement: 'P256-04', kind: 'behaviour', title: then, given, when, then, citation: { path: DRAFT, clause } })
  }
}

// ---- VC-SDX-K1 --------------------------------------------------------------

// ANC §2.1 container: <record-bytes> DROP <commitment-key> CHECKSIG, minimal push.
const container = (recordBytes, key) => LockingScript.fromASM(`${hex(recordBytes)} OP_DROP ${hex(key)} OP_CHECKSIG`)

async function buildK1() {
  const cases = []
  const add = entry => cases.push(entry)
  const k1Case = async (id, requirement, title, walletName, operation, role, acct, fields, extra = {}) => {
    const root = rootFor(walletName, role, acct, { ep: fields.ep, path: fields.path })
    let derived, result
    if (operation === 'k1key') {
      if (!('path' in fields)) result = root.secp256k1PublicKey
      else { derived = k1Own(root.secp256k1Seed, fields.peer ?? root.secp256k1PublicKey, fields.path); result = derived.publicKey }
    } else if (operation === 'k1peer') {
      derived = k1Theirs(root.secp256k1Seed, fields.peer, fields.path); result = derived.publicKey
    } else fail(`k1Case ${operation}`)
    const stock = await brc100PublicKey(root, operation, fields)
    if (stock.publicKey !== hex(result)) fail(`${id}: module result differs from stock BRC-100 getPublicKey`)
    add({
      id, requirement, kind: 'module', title,
      wallet: walletName,
      request: moduleRequest(operation, role, acct, fields),
      expected: { ciphertext: hex(result) },
      ...(derived ? { intermediate: { sharedPoint: hex(derived.shared), hmac: hex(derived.mac), ...(derived.d === undefined ? {} : { childPrivate: hex(be32(derived.d)) }) } } : {}),
      brc100: stock,
      ...extra
    })
    return { root, derived, result }
  }
  const k1SignCase = async (id, requirement, title, walletName, role, acct, fields, extra = {}) => {
    const root = rootFor(walletName, role, acct, { ep: fields.ep, path: fields.path })
    const child = k1Own(root.secp256k1Seed, fields.peer ?? root.secp256k1PublicKey, fields.path)
    const signed = k1Sign(child.d, fields.hash)
    const stock = await brc100Signature(root, fields)
    if (stock.signature !== hex(signed.signature)) fail(`${id}: k1sign differs from stock BRC-100 createSignature`)
    add({
      id, requirement, kind: 'module', title,
      wallet: walletName,
      request: moduleRequest('k1sign', role, acct, fields),
      expected: { ciphertext: hex(signed.signature) },
      intermediate: { sharedPoint: hex(child.shared), hmac: hex(child.mac), childPrivate: hex(be32(child.d)), publicKey: hex(child.publicKey), rfc6979: hex(signed.raw), normalised: signed.normalised },
      brc100: stock,
      ...extra
    })
    return { child, signed }
  }

  // K1-01: derivation, counterparty symmetry, and equality with stock BRC-100.
  await k1Case('k1key-root-public-key', 'K1-01', '`k1key` without `path` returns the account\'s secp256k1 root public key K = secp256k1_seed·G, with no derivation; stock BRC-100 returns it as the identity key of a wallet whose root is that seed', 'account', 'k1key', 'write', A_ID, {})
  const commitment = await k1Case('k1key-commitment-key', 'K1-01', '`k1key`: the commitment key of a record output, ANC §3.1\'s self-derivation under the signing namespace on the path `account/<accountId>/runtime/<runtimeId>/action/<actionId>`: the same derivation identifier as the record\'s P-256 signing key in VC-P256, on the other curve (KEYS §1.8.4, §1.11.2)', 'account', 'k1key', 'write', A_ID, { path: PATHS.commitment })
  await k1Case('k1key-role-invariance', 'K1-01', 'The same request with role `read` selects the same account root and returns the same key; keyID selects nothing', 'account', 'k1key', 'read', A_ID, { path: PATHS.commitment }, { variants: [{ protocolID: [2, protocolNameOf('k1key', 'write', A_ID)] }, { keyID: 'another key id' }], sameAs: 'k1key-commitment-key' })
  await k1Case('k1key-self-equals-own-root-as-peer', 'K1-01', '`k1key` with `peer` set to the account\'s own secp256k1 root equals `k1key` without `peer` (self)', 'account', 'k1key', 'write', A_ID, { path: PATHS.commitment, peer: A.secp256k1PublicKey }, { sameAs: 'k1key-commitment-key' })
  await k1Case('k1key-topup-lock', 'K1-01', '`k1key`: a funding top-up output lock at level-4 purpose `topup`, ordinal 0 (KEYS §1.6.1)', 'account', 'k1key', 'write', A_ID, { path: PATHS.topup })
  const handoffLock = await k1Case('k1peer-handoff-lock', 'K1-01', '`k1peer`: the writer locks a handoff output to the recipient account\'s secp256k1 root under `sdx handoff`, so only that recipient can spend it (KEYS §1.6.1, §1.7)', 'account', 'k1peer', 'write', A_ID, { path: PATHS.handoff, peer: B.secp256k1PublicKey })
  const handoffKey = await k1Case('k1key-handoff-recipient-side', 'K1-01', '`k1key` with `peer`: the recipient, under its own account tag, derives the same handoff key from its own root and the writer\'s root (counterparty symmetry, KEYS §1.12 item 5)', 'recipient', 'k1key', 'write', B_ID, { path: PATHS.handoff, peer: A.secp256k1PublicKey }, { sameAs: 'k1peer-handoff-lock' })
  same(handoffLock.result, handoffKey.result, 'handoff symmetry')
  await k1Case('k1key-actor-root', 'K1-01', '`k1key` without `path` and role `actor`: the actor root\'s secp256k1 public key', 'actor', 'k1key', 'actor', A_ID, {})
  await k1Case('k1key-actor-persistent-0', 'K1-01', '`k1key` with role `actor`: the secp256k1 key at the actor\'s persistent path `2-sdx delegate-actor/0`, the key a grant records as `actorPubKey_k1` when the actor publishes one (KEYS §2.3)', 'actor', 'k1key', 'actor', A_ID, { path: PATHS.actor(0) })
  await k1Case('k1key-session', 'K1-01', '`k1key` with role `session`: the session root named by the path\'s sessionId gives the session\'s secp256k1 key (KEYS §2.14.2)', 'actor', 'k1key', 'session', A_ID, { path: PATHS.session })

  // K1-02: k1sign, deterministic RFC 6979 low-S DER over the 32 bytes given.
  // A real spend of the record output: the next record's transaction spends the tip.
  const recordBytes = utf8(`LAB_SELF_TEST_ONLY VC-SDX-K1 record ${IDS.recordId}`)
  const nextRecordBytes = utf8(`LAB_SELF_TEST_ONLY VC-SDX-K1 record ${IDS.secondRecordId}`)
  const nextKey = k1Own(A.secp256k1Seed, A.secp256k1PublicKey, PATHS.nextCommitment).publicKey
  const tipLock = container(recordBytes, commitment.result)
  const previous = new Transaction(1, [{ sourceTXID: hex(sha256(utf8('LAB_SELF_TEST_ONLY VC-SDX-K1 synthetic funding'))), sourceOutputIndex: 0, unlockingScript: new UnlockingScript([]), sequence: 0xffffffff }], [{ lockingScript: tipLock, satoshis: 1 }], 0)
  const nextLock = container(nextRecordBytes, nextKey)
  const spending = new Transaction(1, [{ sourceTransaction: previous, sourceOutputIndex: 0, unlockingScript: new UnlockingScript([]), sequence: 0xffffffff }], [{ lockingScript: nextLock, satoshis: 1 }], 0)
  const SIGHASH_ALL_FORKID = 0x41
  const preimage = Uint8Array.from(TransactionSignature.format({
    sourceTXID: previous.id('hex'), sourceOutputIndex: 0, sourceSatoshis: 1, transactionVersion: 1, otherInputs: [], outputs: spending.outputs,
    inputIndex: 0, subscript: tipLock, inputSequence: 0xffffffff, lockTime: 0, scope: SIGHASH_ALL_FORKID
  }))
  const sighash = Uint8Array.from(Hash.hash256(Array.from(preimage)))
  const spend = await k1SignCase('k1sign-commitment-spend', 'K1-02', '`k1sign`: the account spends its chain tip. `hash` is the SIGHASH_ALL|FORKID signature hash of input 0 of the next record\'s transaction, and the key is the tip\'s commitment key (ANC §2.1, §3.1)', 'account', 'write', A_ID, { path: PATHS.commitment, hash: sighash })
  spending.inputs[0].unlockingScript = UnlockingScript.fromASM(`${hex(spend.signed.signature)}${SIGHASH_ALL_FORKID.toString(16)}`)
  const valid = new Spend({
    sourceTXID: previous.id('hex'), sourceOutputIndex: 0, sourceSatoshis: 1, lockingScript: tipLock, transactionVersion: 1, otherInputs: [],
    outputs: spending.outputs, unlockingScript: spending.inputs[0].unlockingScript, inputSequence: 0xffffffff, inputIndex: 0, lockTime: 0
  }).validate()
  if (!valid) fail('commitment spend does not validate')
  cases.at(-1).transaction = {
    note: 'Synthetic transactions; nothing is broadcast. `previous` carries the record output (output 0, 1 satoshi) and `spending` spends it with the k1sign result followed by the sighash byte 0x41.',
    previous: previous.toHex(), spending: spending.toHex(), inputIndex: 0, sighashType: SIGHASH_ALL_FORKID, preimage: hex(preimage)
  }
  const handoffHash = sha256(sha256(utf8('LAB_SELF_TEST_ONLY VC-SDX-K1 handoff spend preimage')))
  const handoffSpend = await k1SignCase('k1sign-handoff-spend', 'K1-02', '`k1sign` with `peer`: the recipient signs a spend of the handoff output addressed to it, with the key whose public key is the writer\'s `k1peer` lock', 'recipient', 'write', B_ID, { path: PATHS.handoff, peer: A.secp256k1PublicKey, hash: handoffHash })
  same(handoffSpend.child.publicKey, handoffLock.result, 'handoff spend key is the lock')
  const picks = {}
  for (let i = 0; !(picks.normalised && picks.unchanged); i++) {
    const hash = sha256(sha256(utf8(`LAB_SELF_TEST_ONLY VC-SDX-K1 top-up spend ${i}`)))
    const child = k1Own(A.secp256k1Seed, A.secp256k1PublicKey, PATHS.topup)
    const slot = k1Sign(child.d, hash).normalised ? 'normalised' : 'unchanged'
    if (!picks[slot]) picks[slot] = hash
  }
  await k1SignCase('k1sign-normalised', 'K1-02', '`k1sign` on the top-up key: the RFC 6979 s is above n/2 and is returned as n - s', 'account', 'write', A_ID, { path: PATHS.topup, hash: picks.normalised })
  await k1SignCase('k1sign-unchanged', 'K1-02', '`k1sign` on the top-up key: the RFC 6979 s is already at most n/2 and is returned unchanged', 'account', 'write', A_ID, { path: PATHS.topup, hash: picks.unchanged })

  // K1-03: root selection on secp256k1.
  const second0 = DERIVED.secondEpoch0.root, second1 = DERIVED.secondEpoch1.root
  await k1Case('k1key-second-account-root', 'K1-03', `Two accounts in one wallet: the tag of ${A2_ID} selects that account at its current epoch 1; the result is the K that \`open\` returns`, 'account', 'k1key', 'write', A2_ID, {}, { differsFrom: 'k1key-root-public-key' })
  await k1Case('k1key-second-account-epoch-0', 'K1-03', '`ep` 0 selects the older epoch\'s root', 'account', 'k1key', 'write', A2_ID, { ep: 0 }, { differsFrom: 'k1key-second-account-root' })
  await k1Case('k1key-second-account-commitment', 'K1-03', `The commitment key of ${A2_ID}'s record at the current epoch: ANC §3.1 uses the key tree of the epoch active when the record is written`, 'account', 'k1key', 'write', A2_ID, { path: PATHS.secondCommitment })
  const old = await k1Case('k1key-second-account-commitment-epoch-0', 'K1-03', 'The same commitment path at epoch 0 derives from the epoch-0 root', 'account', 'k1key', 'write', A2_ID, { path: PATHS.secondCommitment, ep: 0 }, { differsFrom: 'k1key-second-account-commitment' })
  const oldHash = sha256(sha256(utf8('LAB_SELF_TEST_ONLY VC-SDX-K1 spend of an epoch-0 entry')))
  const oldSpend = await k1SignCase('k1sign-second-account-epoch-0', 'K1-03', '`k1sign` with `ep` 0: the outgoing epoch\'s key spends a tip committed under it, as a rotation\'s anchoring transaction does with its first input once epoch 1 is open (KEYS §1.10.2 step 5; ANC §3.1)', 'account', 'write', A2_ID, { path: PATHS.secondCommitment, hash: oldHash, ep: 0 })
  same(oldSpend.child.publicKey, old.result, 'epoch-0 spend key')
  if (hex(second0.secp256k1PublicKey) === hex(second1.secp256k1PublicKey)) fail('epoch roots coincide')
  const selection = (id, title, walletName, operation, role, acct, fields, error) => add({ id, requirement: 'K1-03', kind: 'request-rejection', scope: 'selection', title, wallet: walletName, request: moduleRequest(operation, role, acct, fields), expected: { error } })
  selection('k1-unknown-account', `A tag that names no account the wallet holds (${NEW_ID}), although a standing grant names it`, 'account', 'k1key', 'write', NEW_ID, {}, 'unknown-account')
  selection('k1-unknown-epoch', `\`ep\` 2, which ${A2_ID} does not have`, 'account', 'k1key', 'write', A2_ID, { ep: 2 }, 'unknown-epoch')
  selection('k1-epoch-with-actor-role', 'Role `actor` with `ep`', 'actor', 'k1key', 'actor', A_ID, { ep: 0 }, 'epoch-not-allowed')
  selection('k1-epoch-with-session-role', 'Role `session` with `ep`', 'actor', 'k1key', 'session', A_ID, { path: PATHS.session, ep: 0 }, 'epoch-not-allowed')
  selection('k1-session-without-path', 'Role `session` without `path`: no session root is selected', 'actor', 'k1key', 'session', A_ID, {}, 'session-not-selected')
  selection('k1-recipient-holds-no-such-account', `The recipient wallet asked for ${A_ID}, an account it does not hold, although a standing grant names it`, 'recipient', 'k1key', 'write', A_ID, {}, 'unknown-account')

  // K1-04: rejections.
  const hash = sighash
  for (const { name, encoding, error, description, reducesTo } of invalidEncodings('secp256k1', B.secp256k1PublicKey)) {
    const positions = [
      ['k1key', 'peer', moduleRequest('k1key', 'write', A_ID, { path: PATHS.handoff, peer: encoding })],
      ['k1peer', 'peer', moduleRequest('k1peer', 'write', A_ID, { path: PATHS.handoff, peer: encoding })],
      ['k1sign', 'peer', moduleRequest('k1sign', 'write', A_ID, { path: PATHS.commitment, peer: encoding, hash })]
    ]
    add({
      id: `k1-point-${name}`, requirement: 'K1-04', kind: 'point-rejection',
      title: `Rejected before multiplication on secp256k1: ${description}`,
      wallet: 'account',
      curve: 'secp256k1',
      encoding: hex(encoding),
      ...(reducesTo ? { reducesTo } : {}),
      requests: positions.map(([operation, field, req]) => ({ operation, field, ...req })),
      expected: { error }
    })
  }
  // KEYS §1.12 item 7 on secp256k1: no search finds an offset of 0 or at least n (probability about
  // 2^-128), so the rule is pinned as a computation. VC-P256 pins it through module requests with a
  // P-256 offset found by search.
  add({
    id: 'offset-range-secp256k1', requirement: 'K1-04', kind: 'offset-range',
    title: 'Injected secp256k1 HMAC outputs: 0 and values >= n fail, 1 and n - 1 are accepted, nothing is reduced (KEYS §1.12 item 7; the reading of KEYS §1.8.2 in decision D-OFFSET)',
    curve: 'secp256k1', injected: true,
    values: [[0n, 'reject'], [1n, 'accept'], [NK - 1n, 'accept'], [NK, 'reject'], [NK + 1n, 'reject'], [(1n << 256n) - 1n, 'reject']].map(([v, expected]) => ({ hmac: hex(be32(v)), expected }))
  })
  const reject = (id, scope, title, req, error, walletName = 'account') => add({ id, requirement: 'K1-04', kind: 'request-rejection', scope, title, wallet: walletName, request: req, expected: { error } })
  for (const operation of ['k1key', 'k1peer', 'k1sign']) {
    const fields = { k1key: { path: PATHS.commitment }, k1peer: { path: PATHS.handoff, peer: B.secp256k1PublicKey }, k1sign: { path: PATHS.commitment, hash } }[operation]
    reject(`decrypt-with-${operation}`, 'carrier', `\`decrypt\` carrying \`${operation}\`: only \`decrypt\` travels on \`decrypt\``, request('decrypt', protocolNameOf(operation, 'write', A_ID), fields), 'wrong-carrier')
  }
  reject('k1-unknown-operation', 'operation', 'An operation the scheme does not define (`k1verify`)', request('encrypt', protocolNameOf('k1verify', 'write', A_ID), { path: PATHS.commitment, hash }), 'unknown-operation')
  reject('k1sign-privileged', 'grant', '`k1sign` with `privileged: true`', moduleRequest('k1sign', 'write', A_ID, { path: PATHS.commitment, hash }, { privileged: true, privilegedReason: 'LAB_SELF_TEST_ONLY' }), 'privileged-not-supported')
  reject('k1key-counterparty-anyone', 'counterparty', '`k1key` with BRC-100 `counterparty` `anyone`: counterparties travel as `peer`', moduleRequest('k1key', 'write', A_ID, { path: PATHS.commitment }, { counterparty: 'anyone' }), 'counterparty-not-self')
  reject('k1key-counterparty-public-key', 'counterparty', '`k1key` with BRC-100 `counterparty` set to a public key', moduleRequest('k1key', 'write', A_ID, { path: PATHS.handoff }, { counterparty: hex(B.secp256k1PublicKey) }), 'counterparty-not-self')
  reject('k1sign-encryption-namespace', 'path', '`k1sign` for a path in the encryption namespace (KEYS §1.7, §1.11.2)', moduleRequest('k1sign', 'write', A_ID, { path: identifier(NAMESPACES.encrypt, KEY_PATHS.record), hash }), 'namespace-encryption')
  reject('k1key-namespace-unregistered', 'path', '`k1key` for a path in a namespace the profile does not register', moduleRequest('k1key', 'write', A_ID, { path: identifier('sdx bogus', KEY_PATHS.record) }), 'namespace-unregistered')
  reject('k1key-namespace-rotation', 'path', '`k1key` under `sdx rotation`, which SDX reserves (KEYS §1.7, §1.10.3)', moduleRequest('k1key', 'write', A_ID, { path: identifier(NAMESPACES.rotation, KEY_PATHS.record) }), 'namespace-rotation')
  reject('k1sign-namespace-rotation', 'path', '`k1sign` under `sdx rotation`: a rotation\'s anchoring input spends the tip with the commitment key under the signing namespace (KEYS §1.10.2 step 5)', moduleRequest('k1sign', 'root', A_ID, { path: identifier(NAMESPACES.rotation, KEY_PATHS.record), hash }), 'namespace-rotation')
  reject('k1key-purpose-unregistered', 'path', '`k1key` for a level-4 purpose the profile does not register (KEYS §1.6.1, §1.12 item 10)', moduleRequest('k1key', 'write', A_ID, { path: identifier(NAMESPACES.sign, `${KEY_PATHS.record}/refund/0`) }), 'purpose-unregistered')
  reject('k1key-path-record-keyword', 'path', '`k1key` with the level-3 keyword `record`: the laboratory profile names a record `action` on both curves (decision D-PROFILE)', moduleRequest('k1key', 'write', A_ID, { path: identifier(NAMESPACES.sign, `${SCOPE}/record/${IDS.recordId}`) }), 'key-path-grammar')
  for (const [id, value, error, title] of [
    ['k1sign-hash-31-bytes', new Uint8Array(31).fill(0x11), 'hash-length', '31 bytes'],
    ['k1sign-hash-33-bytes', new Uint8Array(33).fill(0x11), 'hash-length', '33 bytes'],
    ['k1sign-hash-empty', new Uint8Array(0), 'hash-length', 'zero bytes'],
    ['k1sign-hash-as-text', hex(hash), 'member-type', 'a hex text string instead of bytes']
  ]) reject(id, 'input', `\`k1sign\` whose \`hash\` is ${title}; it must be exactly 32 bytes`, moduleRequest('k1sign', 'write', A_ID, { path: PATHS.commitment, hash: value }), error)
  reject('k1sign-without-hash', 'input', '`k1sign` without `hash`', moduleRequest('k1sign', 'write', A_ID, { path: PATHS.commitment }), 'missing-member')
  reject('k1sign-without-path', 'input', '`k1sign` without `path`', moduleRequest('k1sign', 'write', A_ID, { hash }), 'missing-member')
  reject('k1sign-with-msg', 'input', '`k1sign` with `msg`, which only `sign` defines', moduleRequest('k1sign', 'write', A_ID, { path: PATHS.commitment, hash, msg: utf8('LAB_SELF_TEST_ONLY') }), 'unknown-member')
  reject('k1peer-without-peer', 'input', '`k1peer` without `peer`', moduleRequest('k1peer', 'write', A_ID, { path: PATHS.handoff }), 'missing-member')
  reject('k1peer-without-path', 'input', '`k1peer` without `path`', moduleRequest('k1peer', 'write', A_ID, { peer: B.secp256k1PublicKey }), 'missing-member')
  reject('k1key-peer-without-path', 'input', '`k1key` with `peer` but no `path`', moduleRequest('k1key', 'write', A_ID, { peer: B.secp256k1PublicKey }), 'missing-member')
  reject('k1-no-grant-from-sign', 'grant', '`k1sign` with role `root`, where only `sign` with role `root` is granted: a `sign` grant does not cover `k1sign`', moduleRequest('k1sign', 'root', B_ID, { path: identifier(NAMESPACES.sign, actionOf(scopeOf(B_ID), IDS.recordId)), hash }), 'no-grant', 'recipient')
  reject('k1-account-isolation', 'grant', `\`k1peer\` for ${A2_ID}, where \`k1peer\` is granted only for ${A_ID}`, moduleRequest('k1peer', 'write', A2_ID, { path: PATHS.handoff, peer: B.secp256k1PublicKey }), 'no-grant')
  reject('k1-no-grant-unheld-account', 'grant', `\`k1key\` with role \`read\` for ${NEW_ID}, an account the wallet does not hold, with no grant for it: refused as not granted, so the refusal does not show whether the wallet holds the account`, moduleRequest('k1key', 'read', NEW_ID, {}), 'no-grant')
  reject('k1-path-outside-grant', 'grant', '`k1sign` for another account whose ID extends the granted one; the prefix ends at a "/"', moduleRequest('k1sign', 'write', A_ID, { path: identifier(NAMESPACES.sign, actionOf(`${KEYWORDS.account}/${A_ID}X/${KEYWORDS.runtime}/${IDS.runtimeId}`, IDS.recordId)), hash }), 'path-not-granted')

  // K1-05: behavioural rows.
  const k1sign = `[2, "${protocolNameOf('k1sign', 'write', A_ID)}"]`
  const rows = [
    ['seek-permission-false', `No grant exists for the originator and ${k1sign}.`, 'The application calls `encrypt` with `seekPermission: false`.', 'The call fails and no prompt is shown.', 'Permissions'],
    ['sign-grant-does-not-cover-k1sign', `A grant exists for [2, "${protocolNameOf('sign', 'write', A_ID)}"].`, 'The application calls `k1sign` under the same logical protocol ID.', 'The `sign` grant does not satisfy it; each operation is granted separately (request vector k1-no-grant-from-sign).', 'Permissions'],
    ['account-isolation', `A grant exists for ${k1sign}.`, `The application calls \`k1sign\` with the tag of ${A2_ID}.`, 'The grant does not satisfy it (request vector k1-account-isolation).', 'Permissions'],
    ['k1sign-prompt-content', 'No grant exists.', 'The application calls `k1sign`.', 'The trusted UI shows the operation, the role, the account tag, `keyID`, `path` and `hash`.', 'Permissions'],
    ['k1sign-signs-given-hash', 'Any wallet state.', 'The application calls `k1sign` with a 32-byte `hash`.', 'The module signs exactly those 32 bytes without hashing them again; it trusts the application to have computed the transaction\'s signature hash, and the prompt shows the hash, the path and the account.', 'Containment'],
    ['containment', 'Any request.', 'Any secp256k1 operation succeeds.', 'The result is a 33-byte public key or a DER signature; it is never `ikm`, `d`, a seed, a child private key or an ECDH secret.', 'Containment']
  ]
  for (const [id, given, when, then, clause] of rows) {
    add({ id: `k1-behaviour-${id}`, requirement: 'K1-05', kind: 'behaviour', title: then, given, when, then, citation: { path: DRAFT, clause } })
  }

  return {
    schema: 'tpnil-sdx-vectors@0.1.0',
    suite: 'VC-SDX-K1',
    claim: 'LAB_SELF_TEST_ONLY',
    status: 'PROPOSED',
    title: 'SDX accounts in a BRC-98 module (`p sdx`), secp256k1 operations: `k1key`, `k1peer`, `k1sign`, account and epoch selection, and rejections',
    requirements: ['K1-01', 'K1-02', 'K1-03', 'K1-04', 'K1-05'],
    citations: [
      { path: DRAFT, clause: 'Scheme, operations and carrier methods' },
      { path: DRAFT, clause: 'Roots and selection' },
      { path: DRAFT, clause: 'Canonical derivation: one root for both curves' },
      { path: DRAFT, clause: 'Point validation' },
      { path: DRAFT, clause: 'Permissions' },
      { path: DRAFT, clause: 'Path scoping' },
      { path: DRAFT, clause: 'Containment' },
      { path: PROGRAM, clause: 'requirements K1-01, K1-02, K1-03, K1-04, K1-05' },
      { path: KEYS, clause: '§1.3.1' },
      { path: KEYS, clause: '§1.6.1' },
      { path: KEYS, clause: '§1.7' },
      { path: KEYS, clause: '§1.8.1' },
      { path: KEYS, clause: '§1.8.2' },
      { path: KEYS, clause: '§1.8.3' },
      { path: KEYS, clause: '§1.8.4' },
      { path: KEYS, clause: '§1.10.2' },
      { path: KEYS, clause: '§1.11.2' },
      { path: KEYS, clause: '§1.12' },
      { path: KEYS, clause: '§2.3' },
      { path: KEYS, clause: '§2.14.2' },
      { path: ANC, clause: '§2.1' },
      { path: ANC, clause: '§3.1' },
      { path: 'https://www.rfc-editor.org/rfc/rfc6979', clause: '§3.2' },
      brc(42, 'Specification'),
      brc(43, 'Specification'),
      brc(98, 'Specification'),
      brc(229, 'Logical protocol ID; Point validation')
    ],
    decisions: DECISIONS.k1,
    profile: profile(),
    testKeys: testKeys(['account', 'recipient', 'actor', 'session']),
    wallets: walletsTable(['account', 'recipient', 'actor']),
    generator: generator(),
    oracles: K1_ORACLES(),
    cases
  }
}

const DRAFT_STATEMENT = 'sdx module draft statement'
const DECISIONS = {}
DECISIONS.common = [
  { id: 'D-SIGN-LOW-S', decision: 'The module\'s `sign` computes ES256 with an RFC 6979 nonce over SHA-256(msg) and returns `r || s` (32 bytes each) in low-S form: when s > n/2 it returns n - s. The output is deterministic. Verifiers accept either S.', basis: `${DRAFT_STATEMENT} §Canonical derivation step 4. KEYS §1.8.3 says producers SHOULD canonicalise to low-S and verifiers SHOULD accept either form; the draft makes low-S the module's rule so that results are reproducible. RFC 6979 A.2.5 cases record the RFC's raw (r, s) and the low-S form.` },
  { id: 'D-PATH', decision: '`path` is the full SDX derivation identifier `2-<namespace>-<keyPath>`, used byte for byte with no Unicode normalisation. Its security level is 2, and its namespace is one the profile registers for the operation\'s curve (`wallets.profile.namespaces`). Nothing is derived under the rotation namespace. `decrypt` takes only paths in the encryption namespace, and `sign` and `k1sign` never take one. The key path is 1 to 1,033 bytes. For roles write, read, root and session it follows KEYS §1.6.1 with the profile\'s keywords and purposes: `account/<id>`, then `runtime/<id>`, then `action/<id>` with an optional `<purpose>/<id>` whose purpose the profile registers, or `session/<id>`. The delegation variant is refused. For role actor the only key path is `actor/<index>` under the delegation namespace, `<index>` decimal with no leading zero. `key` and `k1key` without `path` return the root public key with no derivation, and with `peer` and no `path` they are rejected. Every other operation that derives requires `path`.', basis: `${DRAFT_STATEMENT} §Scheme, operations and carrier methods ("Namespace separation", "Key paths") and §Path scoping; KEYS §1.3 (key paths of 1 to 1033 bytes), §1.6.1 ("A <purpose> the validator does not recognise MUST be rejected at the derivation boundary"; one shared constant), §1.7 ("MUST NOT derive under a namespace absent from their deployment's profile"; the rotation role is reserved where rotation envelopes sign under the signing namespace, as KEYS §1.10.3 step 5 has them), §1.8.1, §1.11.2 ("The derivation library does not enforce the separation, so implementations MUST"), §1.12 item 10, §2.14.1.` },
  { id: 'D-OFFSET', decision: 'A child offset of 0 or >= n fails the derivation; it is never reduced mod n. This is a laboratory reading of a clause that contradicts itself.', basis: `KEYS §1.8.2 computes the scalar as "int(hmac, big-endian) mod N" and then requires the derivation to fail when the scalar "is greater than or equal to N", which the reduction makes unreachable. KEYS §1.12 item 7 requires a known-answer test in which a scalar equal to N and one greater than N each raise the typed rejection, which only the unreduced value can give. The laboratory and ${DRAFT_STATEMENT} §Canonical derivation step 3 apply the rule to the unreduced value.` },
  { id: 'D-SEED', decision: 'A seed outside [1, n - 1] makes the ikm unusable; it is never clamped. Both seeds are checked before either is used.', basis: `${DRAFT_STATEMENT} §Canonical derivation step 2; KEYS §1.4.3.` },
  { id: 'D-ROOTS', decision: 'Test roots are fixed 64-byte ikm values: 0x00..0x3f (account 3MNQpxFAsp), 0x40..0x7f (recipient account 9VxTqR3mLp), 0x80..0xbf (the actor root), 0xc0..0xff (a session root); plus one searched ikm that is unusable. Account 5QkVr9TzWm has two epochs derived from the wallet root SHA-256 of a published label. They are public test key material, not secrets, never funded. The `wallets` table states which wallet holds which root.', basis: 'Lab decision.' },
  { id: 'D-PROFILE', decision: 'The suite uses the laboratory deployment profile, fixtures/sdx/v1/deployment-profile.json, copied into `profile` and `wallets.profile`: format identifier `tpnil-sdx-lab:v1`, and SDX\'s example labels, namespaces, key-path keywords and purposes, for the laboratory only. One level-3 keyword, `action`, names a record on both curves: the P-256 signing key and recipient keys (ENV §8.5, §8.6) and the secp256k1 commitment key (ANC §3.1) of one record share the key path `account/<accountId>/runtime/<runtimeId>/action/<actionId>`.', basis: `KEYS §1.3.1 (a deployment fixes and publishes its profile), §1.6.1 (a keyword is a profile value, and a profile "spells it that way everywhere"), §1.8.4 (the P-256 envelope signature and the secp256k1 transaction signature both use action/<actionId>), §1.11.2 (one key-path grammar on both curves); ANC §3.1; ENV §2.1. Source finding: ENV §8.5 and §8.6 write the record key path account/<account-id>/<writer-scope>/<writer-id>/record/<record-id> and make its segment literals profile parameters, while KEYS writes action; the laboratory reads the ENV literals as example values and fixes them to KEYS's words.` },
  { id: 'D-LOGICAL', decision: 'The protocol name is `p sdx <operation> <role> <h>`. The logical protocol ID is exactly `<role> <h>`: `<role>` is one of write, read, root, actor and session, and `<h>` is the 32-character lowercase hex of the first 16 bytes of SHA-256(UTF-8 accountId). Any other form is rejected.', basis: `${DRAFT_STATEMENT} §Scheme, operations and carrier methods; BRC-98; BRC-229 Logical protocol ID.` },
  { id: 'D-SELECT', decision: 'Roles write, read and root select the account whose tag is `<h>`, at epoch `ep`, or at the current epoch (the highest the wallet holds) when `ep` is absent; an unknown tag or epoch is rejected once the request is authorized (D-ERRORS). Role actor uses the wallet\'s actor root and role session the session root named by the `<sessionId>` segment that follows `/session/` in `path`; for both, `<h>` only scopes grants, and `ep` is rejected. A session request whose path names no session is rejected, and so is one without `path`. A path naming a session the wallet does not hold draws a fresh root (behavioural).', basis: `${DRAFT_STATEMENT} §Roots and selection. The draft does not say what a session request without a session in its path selects; the laboratory rejects it.` },
  { id: 'D-OPEN', decision: '`open` needs role `root` and a tag equal to tag(acct). For an epoch the wallet holds it returns R || K, 66 bytes, under a standing grant. For an account or epoch the wallet does not hold it derives the epoch from the wallet root with key ID "<acct> <ep>" and returns its R || K; creation always prompts, and the vectors mark the approved prompt with `prompt: "approve"`. Without `ep`, `open` of an unknown account creates epoch 0.', basis: `${DRAFT_STATEMENT} §Roots and selection ("open"), §Permissions ("open prompts whenever it creates"), §Canonical derivation step 1.` },
  { id: 'D-SCOPE', decision: 'Each grant covers one [2, "p sdx <operation> <role> <h>"] for one originator and records the derivation-identifier prefixes it covers; the prompt shows them. A request whose `path` does not start with a covered prefix is rejected; a prefix that ends inside a key path ends with "/". A request without `path` needs only a grant for its protocol. Requests use security level 2 and counterparty `self`; `privileged: true` is rejected. Each operation and each account is granted separately. The vectors model grants in `wallets.entries.<wallet>.grants`.', basis: `${DRAFT_STATEMENT} §Permissions ("Grant scope", "Account isolation", "Grant independence") and §Path scoping.` },
  { id: 'D-ANYONE', decision: 'On P-256, `anyone` is the point G (private key 1), as BRC-43 defines it on secp256k1. The module rejects BRC-100 `counterparty` values other than `self`, so `anyone` appears only in rejection cases.', basis: 'BRC-43 counterparty `anyone`.' },
  { id: 'D-CALLS', decision: 'Module calls use security level 2 and keyID "1". All requests come from one lab originator.', basis: 'Lab decision.' },
  { id: 'D-ERRORS', decision: 'Error codes such as `scalar-rejected` and `point-x-range` are laboratory labels. The draft defines no codes; conformance requires the rejection, not the label. The laboratory checks in this order, so a module that checks in the same order gives the same label: the method and reserved names; the protocol name (scheme, operation, carrier method, security level, privileged, logical protocol ID); counterparty; the CBOR input (encoding, members, types, point validation, `hash` length, and the shape of `jwe` with its ephemeral key); `open`\'s role and tag; the path: its form, a namespace registered for the curve, the rotation namespace, the encryption namespace for `decrypt`, `sign` and `k1sign`, the key path\'s length, then its grammar and purpose; the selection checks that read only the request (`ep` on the actor and session roles, the session a path names); the grant and its prefixes, or the approved prompt, which `open` needs whenever it creates; root selection from what the wallet holds (account, epoch, a tag another account holds, a wallet that cannot create); derivation; then, for `decrypt`, the JOSE steps. Checks that read what the wallet holds come after authorization, so a request with no grant and no approval is refused alike whether or not the wallet holds its account or epoch.', basis: `Lab decision. The order of authorization and root selection follows ${DRAFT_STATEMENT} §Permissions and §Errors.` }
]
DECISIONS.vc = [
  ...DECISIONS.common,
  { id: 'D-WALLET-ROOT', decision: 'For an account created inside a wallet, the wallet derives the 64-byte ikm from its own root and nothing else holds it: d is the BRC-42 child private key for protocol [2, "admin sdx root"], key ID "<accountId> <epoch>" (the account ID as issued, a space, the epoch in decimal) and counterparty self, so the BRC-43 invoice number is "2-admin sdx root-<accountId> <epoch>"; ikm = HKDF-SHA-256(IKM = d as 32 bytes big-endian, salt UTF-8 "p sdx v1", info UTF-8 "sdx root", L = 64). An actor root uses key ID "actor". d is never used as a key and never leaves the wallet. The KEYS §1.4.2 split then runs unchanged. The account ID and epoch are inputs, so recovering these accounts needs the wallet root and the account list.', basis: `${DRAFT_STATEMENT} §Canonical derivation step 1 ("Accounts created in the wallet", "Actor wallets") and §Account list and recovery; KEYS §1.4.1 (root keying material is exactly 64 bytes; mnemonic, passphrase and key-service sources are listed as examples); BRC-42; BRC-43; BRC-44 (the admin prefix); BRC-206 "Canonical seed derivation" uses the same pattern for its seed.` },
  { id: 'D-IDS', decision: 'In key paths, `sessionId` is the lowercase hex of 16 bytes. The refusal case for the delegation variant writes `delId` the same way and `actorPubKey` as the lowercase hex of the SEC1-compressed point.', basis: `KEYS §1.6.2 gives no text form for these identifiers; KEYS §2.3 (delId is bstr(16)) and §2.14.1 ("hexadecimal public key"). ${DRAFT_STATEMENT} §Canonical derivation step 1 ("Actor wallets") gives these forms as interpretations.` },
  { id: 'D-ACTOR', decision: 'The actor\'s persistent P-256 key has derivation identifier `2-sdx delegate-actor/<index>`, `<index>` a decimal key index from 0, counterparty `self`, from the actor root. It is the raw key published in the actor\'s DID document and pinned in each grant, and a delegate record signed with it names it in `kid`. It is not a key of any runtime tree, so KEYS §1.6\'s grammar does not govern it, and role actor derives nothing else. The module does not serve the KEYS §1.6.1 delegation variant: its actor-side derivation starts from the grant\'s pinned key, which is not a root the module holds, and KEYS §2.14.1 keeps it off the dispatch path.', basis: `${DRAFT_STATEMENT} §Canonical derivation step 1 ("Actor wallets"); KEYS §2.3, §2.7.2, §2.14.1 ("An actor's envelope signing key is the raw pinned key from the grant's actorPubKey_p256 ... No derivation happens at verification time"). SDX does not fix the persistent path, so it is the draft's recommendation.` },
  { id: 'D-INPUT', decision: 'Inputs are deterministic CBOR maps (RFC 8949 §4.2.1): unsorted or duplicate keys, non-shortest lengths and integers, and indefinite lengths are rejected, as are unknown members, missing required members and members of the wrong major type. `path` and `acct` are text, `ep` an unsigned integer, `jwe` a map, every other member bytes. In the JSON view `jwe` is written as the map itself. `encrypt` with an unknown operation is rejected. P256-03 cases with scope `input`, `path`, `selection` or `grant` extend the row\'s assertion to these rules.', basis: `${DRAFT_STATEMENT} §Scheme, operations and carrier methods (the CBOR inputs bullets and "Other methods"); SDX ENV §3.` },
  { id: 'D-DECRYPT', decision: '`decrypt` carries `{path, peer, jwe}` in `decrypt`\'s `ciphertext` and returns the JWE\'s plaintext as `plaintext`; the content-encryption key never leaves the wallet. `jwe` is one recipient\'s flattened serialization (RFC 7516 §7.2.2) of a general JWE: the shared `protected`, `iv`, `ciphertext` and `tag`, and the recipient\'s `header` and `encrypted_key`. `header` holds only alg, kid, epk, apu and apv, each member sits in `header` or in the protected header and never both, and the joint `alg` is ECDH-ES+A256KW; otherwise the request is refused with `jwe-shape`. The ephemeral key must be a P-256 JWK whose point passes point validation and whose `y` is the point\'s own. The one candidate key is the own P-256 child for `path` and `peer` (ENV §5.3). A wrong key, altered content or an altered protected header gives `decrypt-failed`. The JWEs were made by jose with random content-encryption keys, IVs and ephemeral keys and are frozen; each case records the key agreement Z, the key-encryption key and, when the key is right, the content-encryption key.', basis: `${DRAFT_STATEMENT} §Scheme, operations and carrier methods (the \`decrypt\` row and the \`jwe\` bullet) and §Point validation; ENV §5.2, §5.3, §9, §14, §16; RFC 7516 §7.2; RFC 7518 §4.6.` },
  { id: 'D-SIGNING-INPUT', decision: 'Signed messages are ENV §8.2 JWS signing inputs (protected header `{"alg":"ES256","kid":<kid>}`) over lab payloads, not SDX record encodings.', basis: 'ENV §8.2.' },
  { id: 'D-REPLAY', decision: 'A module case is executable: load `wallets.entries[case.wallet]`, send `request.method` with `request.args` (`plaintext` or `ciphertext` as the hex bytes shown), and compare the result bytes with `expected.ciphertext` or `expected.plaintext`, or confirm a rejection when `expected.error` is set. `variants` repeat the request with the listed argument overrides and expect the same result. Point-rejection cases list one executable request per position. No case needs a test hook in the module.', basis: 'Lab decision.' }
]
DECISIONS.k1 = [
  ...DECISIONS.common.filter(entry => entry.id !== 'D-SIGN-LOW-S' && entry.id !== 'D-ANYONE'),
  { id: 'D-K1-DERIVE', decision: 'secp256k1 child keys are BRC-42 on the selected root k = secp256k1_seed: S = compressed(k·Q) with Q = `peer` or k·G for self, h = HMAC-SHA-256(S, UTF-8(path)) read big-endian, rejected when 0 or >= n; `k1key` returns (k + h)·G and `k1peer` Q + h·G. Each result equals stock BRC-100 getPublicKey of a wallet whose root is k, with protocol [s, <namespace>] and key ID <keyPath> read from the derivation identifier, counterparty `self` or the peer\'s hex, and forSelf true for `k1key`; without `path`, `k1key` equals that wallet\'s identity key. The generator fails if @bsv/sdk 4.0.1 ProtoWallet gives any other value, and each case records the stock call in `brc100`.', basis: `${DRAFT_STATEMENT} §Canonical derivation step 3 ("On secp256k1, SDX's derivation identifier is a BRC-43 invoice number"); KEYS §1.8.1, §1.8.2; BRC-42; BRC-43.` },
  { id: 'D-K1-SIGN', decision: '`k1sign` signs the 32 bytes of `hash` as given, with no further hashing, using the own child key, an RFC 6979 nonce (HMAC-SHA-256, h1 = hash mod n) and low-S canonicalisation, and returns the DER encoding with no sighash byte. The result equals stock BRC-100 createSignature with `hashToDirectlySign` on the same derivation, recorded in `brc100`. It signs under the signing namespace (chain tips and top-up outputs) and the handoff namespace (handoff outputs addressed to the account).', basis: `${DRAFT_STATEMENT} §Canonical derivation step 4 and the \`k1sign\` row; KEYS §1.6.1, §1.7, §1.8.3; RFC 6979 §3.2.` },
  { id: 'D-K1-POINT', decision: '`peer` in `k1key`, `k1peer` and `k1sign` is validated on secp256k1 before any multiplication: exactly 33 bytes, prefix 02 or 03, x < p on the encoded integer before any reducing parser, on y² = x³ + 7.', basis: `${DRAFT_STATEMENT} §Point validation; BRC-229.` },
  { id: 'D-K1-RANGE', decision: 'An offset of 0, n or more cannot be found by search on secp256k1 (probability about 2^-128), so case offset-range-secp256k1 pins KEYS §1.12 item 7 as a computation on injected values: 0, n, n + 1 and 2^256 - 1 are refused and 1 and n - 1 accepted. VC-P256 pins the same rule through module requests with a P-256 offset above n found by search. No case asks a module for a test hook.', basis: 'KEYS §1.8.2, §1.12 item 7; decision D-OFFSET.' },
  { id: 'D-K1-PATHS', decision: 'The commitment key path is `account/<accountId>/runtime/<runtimeId>/action/<actionId>` under the signing namespace, counterparty self (ANC §3.1, KEYS §1.6.1 level 3), the same derivation identifier as the record\'s P-256 signing key. The handoff lock is level-4 purpose `handoff` with `<refIdHex>` under `sdx handoff`, counterparty the recipient\'s secp256k1 root. The top-up lock is purpose `topup`, ordinal 0, under the signing namespace.', basis: 'ANC §3.1, §3.4; KEYS §1.6.1, §1.6.2, §1.7, §1.8.4.' },
  { id: 'D-K1-TX', decision: 'Case k1sign-commitment-spend carries synthetic version-1 transactions: `previous` has the record output (ANC §2.1 container with the commitment key, 1 satoshi), and `spending` spends it with lock time 0 and sequence 0xffffffff. `hash` is SHA-256d of the SIGHASH_ALL|FORKID (0x41) preimage of input 0, and the unlocking script pushes the k1sign result followed by 0x41. Nothing is broadcast.', basis: `ANC §2.1, §3.1; ${DRAFT_STATEMENT} §How SDX uses it ("Spend the chain's tip").` },
  { id: 'D-REPLAY', decision: 'A module case is executable: load `wallets.entries[case.wallet]`, send `request.method` with `request.args`, and compare the result with `expected.ciphertext`, or confirm a rejection when `expected.error` is set. `variants` repeat the request with the listed argument overrides. Point-rejection cases list one request per position. No case needs a test hook in the module.', basis: 'Lab decision.' }
]

// ---- main -------------------------------------------------------------------

const FROZEN_NOTE = 'LAB_SELF_TEST_ONLY. JWEs that VC-P256 decrypt cases open, made once by jose 5.10.0 GeneralEncrypt with a random content-encryption key, IV and ephemeral key per recipient, and frozen with the protected header, recipient kids and plaintext they were made for, and their content-encryption key. generate.mjs re-verifies each by decryption on every run.'
const stored = fs.existsSync(FROZEN_FILE) ? JSON.parse(fs.readFileSync(FROZEN_FILE, 'utf8')) : {}
const frozen = { jwe: { ...(stored.jwe ?? {}) }, used: new Set(), changed: Object.keys(stored).some(key => !['note', 'jwe'].includes(key)) }
if (frozen.changed && mode !== '--write') fail('frozen.json holds entries no case uses; run --write')
const documents = { vc: await buildVc(frozen), k1: await buildK1() }
const unused = Object.keys(frozen.jwe).filter(key => !frozen.used.has(key))
if (unused.length) {
  if (mode !== '--write') fail(`frozen.json holds unused entries ${unused.join(', ')}; run --write`)
  for (const key of unused) delete frozen.jwe[key]
  frozen.changed = true
}
const serialise = value => JSON.stringify(value, null, 2) + '\n'
let differences = 0
for (const [key, file] of Object.entries(OUTPUTS)) {
  const target = path.join(REPO, file)
  const text = serialise(documents[key])
  if (mode === '--write') {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, text)
    console.log(`wrote ${file}: ${documents[key].cases.length} cases`)
  } else if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== text) {
    console.error(`differs: ${file}`)
    differences++
  } else console.log(`identical: ${file} (${documents[key].cases.length} cases)`)
}
if (frozen.changed) {
  fs.writeFileSync(FROZEN_FILE, serialise({ note: FROZEN_NOTE, jwe: Object.fromEntries(Object.entries(frozen.jwe).sort(([a], [b]) => a.localeCompare(b))) }))
  console.log('wrote components/sdx/p256/frozen.json')
}
if (differences) process.exit(1)
