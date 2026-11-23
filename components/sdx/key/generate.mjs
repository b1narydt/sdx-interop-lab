#!/usr/bin/env node
// LAB_SELF_TEST_ONLY generator for VA-KEY: the KEYS §1.12 known-answer tests (items 1-11)
// under the laboratory deployment profile, as requests of the laboratory driver contract.
//
// Libraries: @noble/curves and @noble/hashes (P-256 and secp256k1, HKDF, HMAC), and
// @bsv/sdk 4.0.1, an independent implementation of the derivation standard (BRC-42), against
// which every secp256k1 value is cross-checked (KEYS §1.12 item 2). The checkers
// (src/sdx/keys.mjs with src/sdx/ec-p256.mjs; test/sdx_key.py with test/sdx_ec.py) import none
// of them. Every value is deterministic.
//
//   node generate.mjs --write | --check
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { p256 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { KeyDeriver, PrivateKey, PublicKey } from '@bsv/sdk'
import { runCase } from '../../../src/sdx/keys.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO = path.resolve(HERE, '../../..')
const OUTPUT = 'fixtures/sdx/v1/va-key/vectors.json'
const PROFILE_PATH = 'fixtures/sdx/v1/deployment-profile.json'
const PROFILE_BYTES = fs.readFileSync(path.join(REPO, PROFILE_PATH))
const PROFILE = JSON.parse(PROFILE_BYTES.toString('utf8'))
const mode = process.argv[2]
if (process.argv.length !== 3 || !['--write', '--check'].includes(mode)) { console.error('usage: node generate.mjs --write | --check'); process.exit(2) }

const hex = b => Buffer.from(b).toString('hex')
const unhex = t => Uint8Array.from(Buffer.from(t, 'hex'))
const utf8 = t => new TextEncoder().encode(t)
const big = b => BigInt('0x' + (hex(b) || '0'))
const be32 = v => unhex(v.toString(16).padStart(64, '0'))
const fail = m => { throw new Error(`generator self-check failed: ${m}`) }
const CURVES = { p256: { lib: p256, n: p256.Point.CURVE().n }, secp256k1: { lib: secp256k1, n: secp256k1.Point.CURVE().n } }
const LABELS = PROFILE.derivation.curveLabels
const NS = PROFILE.derivation.namespaces
const KW = PROFILE.derivation.keyPath.keywords
const ident = (ns, kp) => `${PROFILE.derivation.securityLevel}-${ns}-${kp}`

// ---- KEYS §1.4.2 and §1.8.2 on noble ---------------------------------------------------------
function split(ikm) {
  const k1 = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.secp256k1), 32)
  const p = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.p256), 32)
  return { secp256k1: k1, p256: p, usable: { secp256k1: big(k1) > 0n && big(k1) < CURVES.secp256k1.n, p256: big(p) > 0n && big(p) < CURVES.p256.n } }
}
function offset(curve, seed, counterparty, id) {
  const { lib, n } = CURVES[curve]
  const shared = lib.getSharedSecret(seed, counterparty, true)
  const mac = hmac(sha256, shared, utf8(id))
  return { shared, mac, h: big(mac), rejected: big(mac) === 0n || big(mac) >= n }
}
function own(curve, seed, counterparty, id) {
  const { lib, n } = CURVES[curve]
  const o = offset(curve, seed, counterparty, id)
  if (o.rejected) return o
  const d = be32((big(seed) + o.h) % n)
  return { ...o, d, pub: lib.getPublicKey(d, true) }
}
function theirs(curve, seed, counterparty, id) {
  const { lib } = CURVES[curve]
  const o = offset(curve, seed, counterparty, id)
  if (o.rejected) return o
  return { ...o, pub: lib.Point.fromHex(hex(counterparty)).add(lib.Point.BASE.multiply(o.h)).toBytes(true) }
}
const pubOf = (curve, seed) => CURVES[curve].lib.getPublicKey(seed, true)

// ---- roots and identities ----------------------------------------------------------------------
const LABEL = 'TPNIL SDX v1 LAB_SELF_TEST_ONLY public test root'
const labelled = name => sha512(utf8(`${LABEL}: ${name}`))
const ROOTS = {
  K1: labelled('VA-KEY 1'),
  K2: labelled('VA-KEY 2'),
  K3: labelled('VA-KEY 3'),
  SEQ: Uint8Array.from({ length: 64 }, (_, j) => j), // the VC-P256 account root, bytes 0..63
  HIGH: Uint8Array.from({ length: 64 }, () => 0xff)
}
// Found by components/sdx/p256/grind and re-verified here: a root whose P-256 seed is at least n,
// and a P-256 signing identifier whose HMAC offset on root SEQ is at least n (KEYS §1.4.3, §1.8.2).
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const crockford16 = counter => Array.from({ length: 16 }, (_, i) => CROCKFORD[Number((BigInt(counter) >> BigInt(5 * (15 - i))) & 31n)]).join('')
const FOUND_SEED_IKM = unhex('ff'.repeat(56) + (1557900713).toString(16).padStart(16, '0'))
const ACCT = '3MNQpxFAsp', RID = '8kRt2wVbZq', AID = '01JB8ZK3QN7T4YVX2C9M5RDPWA'
const recordPath = aid => `${KW.level1}/${ACCT}/${KW.level2}/${RID}/${KW.level3}/${aid}`
const FOUND_PATH = `${KW.level1}/${ACCT}/${KW.level2}/${RID}/${KW.level3}/${AID.slice(0, 10)}${crockford16(6019505901)}`
{
  const s = split(FOUND_SEED_IKM)
  if (!s.usable.secp256k1 || s.usable.p256) fail('found seed root')
  const seq = split(ROOTS.SEQ)
  if (!offset('p256', seq.p256, pubOf('p256', seq.p256), ident(NS.signing, FOUND_PATH)).rejected) fail('found path')
}

// ---- cases -------------------------------------------------------------------------------------
const cases = []
const add = c => { cases.push({ id: `VA-KEY-${String(cases.length + 1).padStart(3, '0')}`, requirement: ['SDX-A-08'], ...c }); return c }
const profileRef = PROFILE_PATH

// Item 1: the root split.
const splitCase = (name, ikm, title, extra = {}) => {
  const s = split(ikm)
  add({ title, item: 1, basis: ['KEYS §1.4.2', 'KEYS §1.4.3', 'KEYS §1.12 item 1'], tag: 'required', request: { op: 'split', profile: profileRef, rootIkm: hex(ikm) }, expect: { secp256k1Seed: hex(s.secp256k1), p256Seed: hex(s.p256) }, ...extra })
  return s
}
for (const name of ['K1', 'K2', 'K3', 'SEQ', 'HIGH']) splitCase(name, ROOTS[name], `Root split of root ${name}: both 32-byte seeds from the full 64 bytes, HKDF-SHA-256 with an empty salt and the profile's labels`)
add({ title: 'Root keying material of 32 bytes is refused: the root must be exactly 64 bytes, and truncation would halve its entropy', item: 1, basis: ['KEYS §1.4.1', 'KEYS §1.4.2'], tag: 'required', request: { op: 'split', profile: profileRef, rootIkm: hex(ROOTS.K1.subarray(0, 32)) }, expect: { refusal: { class: 'key', detail: 'root-length' } } })
add({ title: 'A root whose P-256 seed is at least n (found by search) is refused as unusable, and is never clamped; the secp256k1 seed of the same root is in range, and neither seed is returned', item: 1, basis: ['KEYS §1.4.3'], tag: 'required', request: { op: 'split', profile: profileRef, rootIkm: hex(FOUND_SEED_IKM) }, expect: { refusal: { class: 'key', detail: 'seed-out-of-range' } }, oracle: { p256Seed: hex(split(FOUND_SEED_IKM).p256), n: CURVES.p256.n.toString(16), found: 'components/sdx/p256/grind: ikm = 0xff * 56 || uint64be(1557900713)' } })

// Derivations on both curves (items 2, 3, 5, 8, 9).
const S = Object.fromEntries(Object.entries(ROOTS).map(([k, ikm]) => [k, split(ikm)]))
const derive = ({ title, item, basis, curve, root, namespace, keyPath, counterparty = 'self', side = 'own', tag = 'required', expectIdentifier }) => {
  const seed = S[root][curve]
  const cp = counterparty === 'self' ? pubOf(curve, seed) : unhex(counterparty)
  const id = ident(namespace, keyPath.normalize('NFC'))
  if (expectIdentifier && id !== expectIdentifier) fail(`identifier ${id}`)
  const r = side === 'own' ? own(curve, seed, cp, id) : theirs(curve, seed, cp, id)
  const request = { op: 'derive', profile: profileRef, curve, rootIkm: hex(ROOTS[root]), namespace, keyPath, counterparty, side }
  if (r.rejected) return add({ title, item, basis, tag, request, expect: { refusal: { class: 'key', detail: `offset-out-of-range:${curve}` } }, oracle: { sharedPoint: hex(r.shared), hmac: hex(r.mac) } })
  // KEYS §1.12 item 2: every secp256k1 value equals @bsv/sdk's BRC-42 derivation.
  if (curve === 'secp256k1') {
    const kd = new KeyDeriver(PrivateKey.fromHex(hex(seed)))
    const cpArg = counterparty === 'self' ? 'self' : PublicKey.fromString(counterparty)
    const protocol = [PROFILE.derivation.securityLevel, namespace]
    const sdkPub = side === 'own' ? kd.derivePrivateKey(protocol, keyPath.normalize('NFC'), cpArg).toPublicKey().toString() : kd.derivePublicKey(protocol, keyPath.normalize('NFC'), cpArg).toString()
    if (sdkPub !== hex(r.pub)) fail(`@bsv/sdk disagrees on ${title}`)
  }
  return add({ title, item, basis, tag, request, expect: { identifier: id, publicKey: hex(r.pub), ...(side === 'own' ? { privateKey: hex(r.d) } : {}) }, oracle: { sharedPoint: hex(r.shared), hmac: hex(r.mac) } })
}
const SIGN = recordPath(AID), FIELD = `${recordPath(AID)}/field/photoHash`
// Item 9: the KEYS §1.8.1 worked example is the identifier the laboratory profile produces.
derive({ title: 'Derivation identifier assembly: the KEYS §1.8.1 worked example, `<securityLevel>-<namespace>-<keyPath>` with literal hyphens, and the P-256 field-encryption key it gives on root K1', item: 9, basis: ['KEYS §1.8.1', 'KEYS §1.12 item 9'], curve: 'p256', root: 'K1', namespace: NS.encryption, keyPath: FIELD, expectIdentifier: '2-sdx encrypt-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN7T4YVX2C9M5RDPWA/field/photoHash' })
// Item 3: P-256 derivation, private scalar and public key.
for (const [ns, kp, what] of [[NS.signing, SIGN, 'the per-record signing key (ENV §8.5)'], [NS.encryption, SIGN, 'the writer self-recipient key (ENV §8.6)'], [NS.delegation, `${KW.level1}/${ACCT}/${KW.level2}/${RID}/${KW.level3Session}/ffeeddccbbaa99887766554433221100`, 'a session key (KEYS §2.14.2)']]) {
  derive({ title: `P-256 derivation on root K2: ${what}, private scalar and SEC1-compressed public key, at counterparty self`, item: 3, basis: ['KEYS §1.8.2', 'KEYS §1.12 item 3'], curve: 'p256', root: 'K2', namespace: ns, keyPath: kp })
}
// Item 2: secp256k1, cross-checked against @bsv/sdk; the symmetric key separately below.
derive({ title: 'secp256k1 derivation on root K2: the ANC §3.1 commitment key, the same identifier as the P-256 signing key on the other tree, equal to @bsv/sdk BRC-42', item: 2, basis: ['KEYS §1.8.2', 'KEYS §1.11.2', 'KEYS §1.12 item 2', 'ANC §3.1'], curve: 'secp256k1', root: 'K2', namespace: NS.signing, keyPath: SIGN })
derive({ title: 'secp256k1 derivation of a `topup` output lock on root K2, equal to @bsv/sdk BRC-42', item: 2, basis: ['KEYS §1.6.1', 'KEYS §1.12 item 2'], curve: 'secp256k1', root: 'K2', namespace: NS.signing, keyPath: `${SIGN}/topup/0` })
{
  const seed = S.K2.secp256k1
  const id = ident(NS.encryption, FIELD)
  const d = own('secp256k1', seed, pubOf('secp256k1', seed), id)
  const key = be32(big(secp256k1.getSharedSecret(d.d, d.pub, true).subarray(1)))
  const sdk = new KeyDeriver(PrivateKey.fromHex(hex(seed))).deriveSymmetricKey([2, NS.encryption], FIELD, 'self').toArray('be', 32)
  if (hex(sdk) !== hex(key)) fail('symmetric key: noble vs @bsv/sdk')
  add({ title: 'secp256k1 symmetric field key at counterparty self on root K2: the x-coordinate of the derived private key times the counterparty\'s derived public key (BRC-2), equal to @bsv/sdk deriveSymmetricKey', item: 2, basis: ['KEYS §1.8.2 (Symmetric keys)', 'KEYS §1.8.4', 'KEYS §1.12 item 2'], tag: 'required', request: { op: 'symmetric', profile: profileRef, curve: 'secp256k1', rootIkm: hex(ROOTS.K2), namespace: NS.encryption, keyPath: FIELD, counterparty: 'self' }, expect: { identifier: id, key: hex(key) } })
}
// Item 5: counterparty symmetry on both curves. K1 derives K3's child; K3 derives its own.
for (const curve of ['p256', 'secp256k1']) {
  const path5 = FIELD
  const a = derive({ title: `Counterparty symmetry on ${curve}: root K1 derives the child public key of root K3 (counterparty K3's root public key)`, item: 5, basis: ['KEYS §1.8.2', 'KEYS §1.12 item 5', 'ENV §8.6'], curve, root: 'K1', namespace: NS.encryption, keyPath: path5, counterparty: hex(pubOf(curve, S.K3[curve])), side: 'counterparty' })
  const b = derive({ title: `Counterparty symmetry on ${curve}: root K3 derives its own child with counterparty K1, and its public key equals the one K1 derived`, item: 5, basis: ['KEYS §1.8.2', 'KEYS §1.12 item 5'], curve, root: 'K3', namespace: NS.encryption, keyPath: path5, counterparty: hex(pubOf(curve, S.K1[curve])), side: 'own' })
  if (a.expect.publicKey !== b.expect.publicKey) fail(`symmetry on ${curve}`)
}
// Item 8: NFC normalisation before hashing.
for (const curve of ['p256', 'secp256k1']) {
  const composed = derive({ title: `Normalisation on ${curve}: a field name given as \`a\` followed by U+0301 is normalised to the composed \`á\` before hashing`, item: 8, basis: ['KEYS §1.6.2', 'KEYS §1.12 item 8'], curve, root: 'K1', namespace: NS.encryption, keyPath: `${recordPath(AID)}/field/á` })
  const direct = own(curve, S.K1[curve], pubOf(curve, S.K1[curve]), ident(NS.encryption, `${recordPath(AID)}/field/á`))
  if (composed.expect.publicKey !== hex(direct.pub) || !composed.expect.identifier.endsWith('/field/á')) fail('NFC')
}
// Item 7: scalar rejection. A found P-256 identifier, then injected offsets on both curves.
derive({ title: 'Scalar rejection, found: on root SEQ the HMAC offset of this P-256 signing identifier is at least n, so the derivation fails and the value is never reduced (laboratory reading of KEYS §1.8.2)', item: 7, basis: ['KEYS §1.8.2', 'KEYS §1.12 item 7'], curve: 'p256', root: 'SEQ', namespace: NS.signing, keyPath: FOUND_PATH })
for (const curve of ['p256', 'secp256k1']) {
  const n = CURVES[curve].n
  for (const [label, value, accepted] of [['0', 0n, false], ['1', 1n, true], ['n - 1', n - 1n, true], ['n', n, false], ['n + 1', n + 1n, false], ['2^256 - 1', (1n << 256n) - 1n, false]]) {
    add({ title: `Scalar rejection on ${curve}: an HMAC output of ${label} is ${accepted ? 'accepted as the scalar' : 'refused with a typed error naming the curve'}`, item: 7, basis: ['KEYS §1.8.2', 'KEYS §1.12 item 7'], tag: 'required', hook: true, request: { op: 'offset', curve, hmac: hex(be32(value)) }, expect: accepted ? { scalar: hex(be32(value)) } : { refusal: { class: 'key', detail: `offset-out-of-range:${curve}` } } })
  }
}
// Item 6: curve independence over ten roots.
for (let i = 1; i <= 10; i++) {
  const ikm = labelled(`VA-KEY independence ${i}`)
  const s = split(ikm)
  let bits = 0
  for (let j = 0; j < 32; j++) { let x = s.secp256k1[j] ^ s.p256[j]; while (x) { bits += x & 1; x >>= 1 } }
  if (bits < 100) fail('curve independence')
  splitCase(`I${i}`, ikm, `Curve independence, root ${i} of 10: the two seeds differ in ${bits} of 256 bits (at least 100 required)`, { item: 6, basis: ['KEYS §1.12 item 6'], oracle: { differingBits: bits } })
}
// Item 10: key-path grammar under the profile.
const validate = (title, keyPath, accepted, detail, tag = 'required', basis = ['KEYS §1.6.1', 'KEYS §1.12 item 10']) => add({ title, item: 10, basis, tag, request: { op: 'validate', profile: profileRef, keyPath }, expect: accepted ? { verdict: 'accepted' } : { verdict: 'refused', detail } })
const L2 = `${KW.level1}/${ACCT}/${KW.level2}/${RID}`
for (const p of PROFILE.derivation.keyPath.purposes) validate(`The registered purpose \`${p.purpose}\` at level 4 is accepted`, `${recordPath(AID)}/${p.purpose}/${p.purpose === 'field' ? 'photoHash' : p.purpose === 'topup' ? '0' : 'a1b2c3'}`, true)
validate('The session level-3 variant is accepted', `${L2}/${KW.level3Session}/ffeeddccbbaa99887766554433221100`, true)
validate('A level-3 action path is accepted', recordPath(AID), true)
validate('A level-1 account path is accepted', `${KW.level1}/${ACCT}`, true)
validate('The delegation level-3 variant is accepted', `${L2}/${KW.level3Delegation}/00112233445566778899aabbccddeeff/${KW.delegationActor}/02${'11'.repeat(32)}`, true)
validate('An unregistered level-4 purpose is refused at the derivation boundary', `${recordPath(AID)}/photo/1`, false, 'purpose')
validate('A level-3 keyword the profile does not use (`record`, the ENV §8.5 example literal) is refused under this profile', `${L2}/record/${AID}`, false, 'keyword', 'required', ['KEYS §1.6.1', 'KEYS §1.3.1'])
validate('A path with an empty segment is refused', `${KW.level1}//${KW.level2}/${RID}`, false, 'segment')
validate('A field name carrying `/` breaks the five-level structure and is refused', `${recordPath(AID)}/field/a/b`, false, 'structure')
validate('A key path longer than 1033 bytes is refused', `${recordPath(AID)}/field/${'x'.repeat(1034 - recordPath(AID).length - 7)}`, false, 'length', 'required', ['KEYS §1.3'])
validate('A field name longer than 256 bytes is refused (laboratory choice: KEYS §1.6.2 bounds field names, and the validator applies it)', `${recordPath(AID)}/field/${'x'.repeat(257)}`, false, 'field-name', 'labChoice', ['KEYS §1.6.2'])
add({ title: 'Deriving under a namespace absent from the profile is refused', item: 10, basis: ['KEYS §1.7'], tag: 'required', request: { op: 'derive', profile: profileRef, curve: 'p256', rootIkm: hex(ROOTS.K1), namespace: 'sdx archive', keyPath: SIGN, counterparty: 'self', side: 'own' }, expect: { refusal: { class: 'key', detail: 'namespace' } } })
add({ title: 'Deriving under the rotation namespace is refused: the laboratory profile reserves it and signs rotation records under the signing namespace', item: 10, basis: ['KEYS §1.7', 'KEYS §1.10.3 step 5'], tag: 'labChoice', request: { op: 'derive', profile: profileRef, curve: 'p256', rootIkm: hex(ROOTS.K1), namespace: NS.rotation, keyPath: SIGN, counterparty: 'self', side: 'own' }, expect: { refusal: { class: 'key', detail: 'namespace-reserved' } } })
// Item 11: profile conformance.
const mutate = fn => { const p = structuredClone(PROFILE); fn(p); return p }
const profileCase = (title, document, failures, tag = 'required') => add({ title, item: 11, basis: ['KEYS §1.3', 'KEYS §1.3.1', 'KEYS §1.4.2', 'KEYS §1.6', 'KEYS §1.7', 'KEYS §1.12 item 11'], tag, request: { op: 'profile', profile: document === PROFILE ? profileRef : { inline: document } }, expect: { verdict: failures.length ? 'nonconforming' : 'conforming', failures } })
profileCase('The laboratory profile conforms', PROFILE, [])
profileCase('Two roles with one namespace string do not conform', mutate(p => { p.derivation.namespaces.handoff = p.derivation.namespaces.signing }), ['namespaces-distinct'])
profileCase('Equal per-curve labels do not conform', mutate(p => { p.derivation.curveLabels.p256 = p.derivation.curveLabels.secp256k1 }), ['labels-distinct'])
profileCase('A namespace ending with the word `protocol` does not conform', mutate(p => { p.derivation.namespaces.handoff = 'sdx handoff protocol' }), ['namespace-grammar:handoff'])
profileCase('A namespace with an uppercase letter does not conform', mutate(p => { p.derivation.namespaces.signing = 'SDX sign' }), ['namespace-grammar:signing'])
profileCase('A namespace with a hyphen does not conform', mutate(p => { p.derivation.namespaces.encryption = 'sdx-encrypt' }), ['namespace-grammar:encryption'])
profileCase('A namespace of 4 characters does not conform', mutate(p => { p.derivation.namespaces.delegation = 'sdxd' }), ['namespace-grammar:delegation'])
profileCase('A namespace with two consecutive spaces does not conform', mutate(p => { p.derivation.namespaces.transportAuthentication = 'sdx  transport auth' }), ['namespace-grammar:transportAuthentication'])
profileCase('A key-path keyword containing `/` does not conform', mutate(p => { p.derivation.keyPath.keywords.level2 = 'run/time' }), ['keyword:level2'])
profileCase('Two registered purposes with one name do not conform', mutate(p => { p.derivation.keyPath.purposes.push({ ...p.derivation.keyPath.purposes[0] }) }), ['purposes-distinct'])
profileCase('An empty per-curve label does not conform', mutate(p => { p.derivation.curveLabels.secp256k1 = '' }), ['label:secp256k1'])

// ---- every case through the Node checker ------------------------------------------------------
for (const c of cases) {
  const result = runCase(PROFILE, c)
  if (!result.ok) fail(`${c.id} ${c.title}: ${JSON.stringify(result.actual)}`)
}

const doc = {
  schema: 'tpnil-sdx-vectors@0.1.0',
  suite: 'VA-KEY',
  claim: 'LAB_SELF_TEST_ONLY',
  status: 'BASELINE-v0.1',
  requirements: ['SDX-A-08'],
  profile: { id: PROFILE.profile, path: PROFILE_PATH, sha256: hex(sha256(PROFILE_BYTES)) },
  driverContract: 'programs/proposals/sdx-data-sharing/0.1.0/driver-contract.md',
  citations: ['KEYS §1.3', 'KEYS §1.3.1', 'KEYS §1.4.1', 'KEYS §1.4.2', 'KEYS §1.4.3', 'KEYS §1.6.1', 'KEYS §1.6.2', 'KEYS §1.7', 'KEYS §1.8.1', 'KEYS §1.8.2', 'KEYS §1.12'].map(clause => ({ path: 'fixtures/sdx/v1/standards/text/keys.md', clause })),
  items: {
    1: 'Root split: five roots, a 32-byte root refused, and a found root whose P-256 seed is out of range',
    2: 'secp256k1 derivation and the symmetric field key, each equal to @bsv/sdk 4.0.1 (BRC-42, BRC-2)',
    3: 'P-256 derivation: private scalar and public key for three identifiers',
    4: 'ES256 round trip: exercised on record signatures by VA-SIG (verification, tampered signatures and a wrong signer\'s key)',
    5: 'Counterparty symmetry on both curves',
    6: 'Curve independence over ten roots',
    7: 'Scalar rejection: a found P-256 identifier, and injected offsets 0, 1, n - 1, n, n + 1 and 2^256 - 1 on both curves through the `offset` hook',
    8: 'NFC normalisation on both curves',
    9: 'Derivation-identifier assembly: the KEYS §1.8.1 worked example',
    10: 'Key-path grammar: every registered purpose and variant accepted; an unregistered purpose, a foreign keyword, an empty segment, an extra segment and an over-long path refused; namespaces outside the profile refused',
    11: 'Profile conformance: the laboratory profile and ten non-conforming variants'
  },
  roots: Object.fromEntries(Object.entries(ROOTS).map(([k, v]) => [k, { rootIkm: hex(v), derivedFrom: k === 'SEQ' ? 'bytes 0x00 to 0x3f' : k === 'HIGH' ? '64 bytes 0xff' : `SHA-512("${LABEL}: VA-KEY ${k.slice(1)}")` }])),
  found: {
    seed: { rootIkm: hex(FOUND_SEED_IKM), by: 'components/sdx/p256/grind (seed): ikm = 0xff * 56 || uint64be(1557900713); its P-256 seed is at least n' },
    path: { root: 'SEQ', identifier: ident(NS.signing, FOUND_PATH), by: 'components/sdx/p256/grind (path): the record identifier\'s last 16 characters are the Crockford base32 of 6019505901; the HMAC offset is at least n' }
  },
  decisions: [
    { id: 'deployment-profile', kind: 'Rests on the cited text', text: 'Every value is computed under the laboratory profile `tpnil-sdx-lab:v1`: its labels, namespaces and key-path vocabulary are SDX\'s example values, used in the laboratory only, so the KEYS §1.8.1 worked example is also a laboratory known answer. Basis: KEYS §1.3.1, §1.12.' },
    { id: 'scalar-rejection', kind: 'Laboratory interpretation', text: 'An HMAC offset of 0 or at least n is refused before any reduction, and the value is never reduced. Source finding: KEYS §1.8.2 both reduces the HMAC output modulo n and requires failure at or above n; KEYS §1.12 item 7 tests the rejection, which assumes the check comes first. Injected offsets travel through the optional `offset` hook, because no search can find 0 or n; an implementation without the hook is BLOCKED on those cases. Basis: KEYS §1.8.2, §1.12 item 7.' },
    { id: 'symmetric-key', kind: 'Laboratory interpretation', text: 'The secp256k1 symmetric key is the 32-byte x-coordinate of the shared point between the deriver\'s derived private key and the counterparty\'s derived public key, as BRC-2 and @bsv/sdk define it. Source finding: KEYS §1.8.2 says only that "the resulting shared material" is the key. Basis: KEYS §1.8.2, §1.8.4, §1.12 item 2.' },
    { id: 'symmetry-form', kind: 'Rests on the cited text', text: 'Counterparty symmetry is tested in the KEYS §1.12 item 5 form: one side\'s derived public key equals the other side\'s derived private key\'s public key. Source finding: KEYS §1.8.4 and §2.14.1 say both sides derive the same private key, which the §1.8.2 algorithm does not give (coverage KEYS-1.8).' },
    { id: 'grammar', kind: 'Laboratory test-construction choice', text: 'The `validate` operation applies the profile\'s five-level structure: keyword segments in their positions followed by one identifier each, level 4 only with a registered purpose, the session and delegation variants, no empty segment, and at most 1033 bytes; field names are bounded at 256 bytes (`labChoice`). Basis: KEYS §1.3, §1.6.1, §1.6.2, §1.12 item 10.' },
    { id: 'reserved-rotation', kind: 'Laboratory test-construction choice', text: 'The laboratory profile reserves the rotation namespace and does not derive under it; a derivation request under it is refused (`labChoice`: KEYS §1.7 lets a profile reserve a role). Basis: KEYS §1.7, §1.10.3 step 5.' },
    { id: 'item-4', kind: 'Laboratory test-construction choice', text: 'KEYS §1.12 item 4, the ES256 round trip, is exercised on record signatures by VA-SIG, which verifies signatures under a JOSE implementation in its generator and refuses tampered signatures and a wrong signer\'s key.' }
  ],
  generator: { component: 'components/sdx/key', command: 'npm run generate --prefix components/sdx/key', check: 'npm run check --prefix components/sdx/key', dependencies: JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8')).dependencies, lockfile: 'components/sdx/key/package-lock.json', deterministic: 'Every value is a function of the published roots and the profile.' },
  oracles: {
    generatorWitness: '@bsv/sdk 4.0.1 KeyDeriver equals every secp256k1 derivation and the symmetric key.',
    node: { modules: ['src/sdx/keys.mjs', 'src/sdx/ec-p256.mjs'], kind: 'oracle', dependencies: 'Node.js built-ins only (HKDF and HMAC by node:crypto, scalar multiplication by OpenSSL)', tests: ['test/sdx-key.test.mjs'] },
    python: { modules: ['test/sdx_key.py', 'test/sdx_ec.py'], kind: 'oracle', dependencies: 'Python standard library only', tests: ['test/test_sdx_key.py'] }
  },
  caseCount: cases.length,
  cases
}
const text = JSON.stringify(doc, null, 1) + '\n'
const file = path.join(REPO, OUTPUT)
if (mode === '--write') { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); console.log(`wrote ${OUTPUT} (${cases.length} cases)`) }
else if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== text) { console.error(`${OUTPUT} is not current; run --write`); process.exit(1) }
else console.log(`${OUTPUT} is current (${cases.length} cases)`)
