// LAB_SELF_TEST_ONLY oracle for SDX v0.1 record envelopes (ENV §2, §5-§16) and record
// signatures (ENV §8.2-§8.5; KEYS §2.7.1, §2.7.2 as far as no grant is needed), under the
// laboratory deployment profile. Node.js built-ins only.
//
// This file is an ORACLE, not an implementation. ENV §16 requires implementations to use a
// JOSE implementation; this oracle performs the JOSE steps by hand on node:crypto (ECDH on
// P-256, the RFC 7518 Concat KDF, AES key wrap, AES-GCM and ECDSA verification) so that the
// laboratory can judge a record without trusting any one JOSE library. Curve validation and
// point arithmetic come from src/sdx/ec-p256.mjs, deterministic CBOR from src/sdx/cbor-det.mjs
// and LZMA from src/sdx/lzma.mjs. It imports no generator code.
//
//   readEnvelope(profile, request)   the driver contract's `read`: returns a projection
//   writeRefusal(request)            the writer-side input rules: the refusal detail or null
//   checkWrite(profile, kase, hex)   the write-direction checks on a writer's envelope
//   secrets(data, iterations)        ENV §4 calculateSecrets
//   runCase(profile, kase)           one VA-ENV or VA-SIG case; returns { ok, actual, failures }
import { createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, pbkdf2Sync, verify as cryptoVerify } from 'node:crypto'
import { CborDetError, decode as cborDecode, encode as cborEncode, encodeSuperseded, isDeterministic } from './cbor-det.mjs'
import { CURVES, EcError, addPoints, decodePoint, ecdhPoint, ecdhX, encodePoint, int32, mulBase, toInt } from './ec-p256.mjs'
import { LzmaError, decodeAlone } from './lzma.mjs'

const P256 = CURVES.p256
const ECDH_ALG = 'ECDH-ES+A256KW'
const GCMKW_ALG = 'A256GCMKW'
export const MIN_ITERATIONS = 200000
export const REFUSAL_CLASSES = Object.freeze(['format', 'structure', 'integrity', 'signature', 'decode', 'root-pk-mismatch', 'delegation-invalid'])

export class Refusal extends Error {
  constructor(cls, detail) { super(`${cls}: ${detail}`); this.cls = cls; this.detail = detail }
}
const refuse = (cls, detail) => { throw new Refusal(cls, detail) }
const hex = bytes => Buffer.from(bytes).toString('hex')
const utf8 = text => Buffer.from(text, 'utf8')
const isMap = value => value instanceof Map
const isText = value => typeof value === 'string'
const isUint = value => Number.isSafeInteger(value) && value >= 0
const isBytes = (value, length) => value instanceof Uint8Array && (length === undefined || value.length === length)
const sha256 = bytes => createHash('sha256').update(bytes).digest()

// Canonical base64url: the alphabet, no padding, and no stray bits (ENV §9.1 rule 2).
export function b64uCanonical(text) {
  if (!isText(text) || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null
  const bytes = Buffer.from(text, 'base64url')
  return bytes.toString('base64url') === text ? bytes : null
}
const b64u = bytes => Buffer.from(bytes).toString('base64url')

// ---- KEYS §1.4.2 and §1.8.2 under the profile --------------------------------------------

export function splitRoot(profile, ikm) {
  if (ikm.length !== 64) throw new Error('root keying material must be 64 bytes')
  const labels = profile.derivation.curveLabels
  const seed = label => Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), utf8(label), 32))
  const k1 = seed(labels.secp256k1), p = seed(labels.p256)
  if (toInt(p) === 0n || toInt(p) >= P256.n) throw new Error('p256 seed out of range')
  return { p256Seed: p, k1Seed: k1, R: encodePoint(P256, mulBase(P256, toInt(p))) }
}
const keyPath = (profile, acct, rid, aid) => {
  const kw = profile.derivation.keyPath.keywords
  return `${kw.level1}/${acct}/${kw.level2}/${rid}/${kw.level3}/${aid}`
}
const derivationId = (profile, namespace, path) => `${profile.derivation.securityLevel}-${namespace}-${path}`
export const outerIdentifier = (profile, acct, rid, aid) => derivationId(profile, profile.derivation.namespaces.encryption, keyPath(profile, acct, rid, aid))
export const fieldIdentifier = (profile, acct, rid, aid, name) => `${outerIdentifier(profile, acct, rid, aid)}/field/${name}`
export const signIdentifier = (profile, acct, rid, aid) => derivationId(profile, profile.derivation.namespaces.signing, keyPath(profile, acct, rid, aid))

// The offset h = HMAC-SHA-256(compressed(own x counterparty), identifier), refused at 0 or >= n.
function offset(seed, counterparty, id) {
  const shared = encodePoint(P256, ecdhPoint(P256, toInt(seed), counterparty))
  const h = toInt(createHmac('sha256', shared).update(utf8(id)).digest())
  if (h === 0n || h >= P256.n) throw new Error(`offset out of range for ${id}`)
  return h
}
// The deriver's own child private key and its public key (counterparty: own R for self).
export function ownChild(seed, counterparty, id) {
  const d = (toInt(seed) + offset(seed, counterparty, id)) % P256.n
  return { d, pub: encodePoint(P256, mulBase(P256, d)) }
}
// The counterparty's child public key: h·G + counterparty.
export function theirChild(seed, counterparty, id) {
  const h = offset(seed, counterparty, id)
  return encodePoint(P256, addPoints(P256, mulBase(P256, h), decodePoint(P256, counterparty)))
}

// ---- JOSE steps by hand (oracle) ----------------------------------------------------------

const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }
function concatKdf(z, alg) {
  const lv = bytes => Buffer.concat([u32(bytes.length), bytes])
  return sha256(Buffer.concat([u32(1), z, lv(utf8(alg)), lv(Buffer.alloc(0)), lv(Buffer.alloc(0)), u32(256)]))
}
function aesKwUnwrap(kek, wrapped) {
  const decipher = createDecipheriv('id-aes256-wrap', kek, Buffer.from('a6a6a6a6a6a6a6a6', 'hex'))
  return Buffer.concat([decipher.update(wrapped), decipher.final()])
}
function gcmOpen(key, iv, aad, ciphertext, tag) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  if (aad) decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}
const plain = value => isMap(value) ? Object.fromEntries([...value].map(([k, v]) => [k, plain(v)])) : value
function jwkPoint(jwk) {
  if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk) return null
  const x = b64uCanonical(jwk.x), y = b64uCanonical(jwk.y)
  if (!x || !y || x.length !== 32 || y.length !== 32) return null
  const point = { x: toInt(x), y: toInt(y) }
  try { const encoded = encodePoint(P256, point); const back = decodePoint(P256, encoded); return back.y === point.y ? encoded : null } catch { return null }
}
function protectedObject(text) {
  const bytes = b64uCanonical(text)
  if (!bytes) return null
  try { const value = JSON.parse(bytes.toString('utf8')); return value && typeof value === 'object' && !Array.isArray(value) ? value : null } catch { return null }
}

// ENV §9.1 rule 2: everything the decryption step would validate, checked before a decline is
// honoured. Each failure is an integrity refusal.
export function validateForDecline(jwe, inRecord) {
  const bad = what => refuse('integrity', `slot-validation:${what}`)
  if (!isMap(jwe)) bad('jwe-shape')
  const members = inRecord ? ['protected', 'recipients', 'iv', 'ciphertext', 'tag'] : ['protected', 'recipients', 'iv', 'tag']
  for (const m of members) if (!jwe.has(m)) bad(`missing-${m}`)
  if (!inRecord && jwe.has('ciphertext')) bad('detached-ciphertext')
  for (const m of ['protected', 'iv', 'tag', ...(inRecord ? ['ciphertext'] : [])]) if (!b64uCanonical(jwe.get(m))) bad(`base64url-${m}`)
  if (b64uCanonical(jwe.get('iv')).length !== 12) bad('iv-length')
  if (b64uCanonical(jwe.get('tag')).length !== 16) bad('tag-length')
  const prot = protectedObject(jwe.get('protected'))
  if (!prot) bad('protected')
  if (prot.enc !== 'A256GCM') bad('enc')
  const shared = jwe.has('unprotected') ? plain(jwe.get('unprotected')) : {}
  if (!shared || typeof shared !== 'object') bad('unprotected')
  const recipients = jwe.get('recipients')
  if (!Array.isArray(recipients) || recipients.length === 0) bad('recipients')
  for (const r of recipients) {
    if (!isMap(r)) bad('recipient-shape')
    const header = r.has('header') ? plain(r.get('header')) : {}
    if (!header || typeof header !== 'object') bad('recipient-header')
    const names = [...Object.keys(prot), ...Object.keys(shared), ...Object.keys(header)]
    if (new Set(names).size !== names.length) bad('header-union-repeats')
    const union = { ...prot, ...shared, ...header }
    const ek = b64uCanonical(r.get('encrypted_key'))
    if (!ek) bad('base64url-encrypted_key')
    if (union.alg === ECDH_ALG) {
      if (!isText(union.kid) || !/^[0-9a-f]{66}$/.test(union.kid)) bad('kid')
      try { decodePoint(P256, Buffer.from(union.kid, 'hex')) } catch { bad('kid-point') }
      if (!jwkPoint(union.epk)) bad('epk')
      if (ek.length !== 40) bad('encrypted_key-length')
    } else if (union.alg === GCMKW_ALG) {
      const kwiv = b64uCanonical(union.iv), kwtag = b64uCanonical(union.tag)
      if (!kwiv || kwiv.length !== 12 || !kwtag || kwtag.length !== 16) bad('gcmkw-iv-tag')
      if (ek.length !== 32) bad('encrypted_key-length')
    } else bad('alg')
  }
}

// Opens a JWE (a decoded CBOR map) through the identity slot whose kid is `kid`, with child
// private key d. Returns the plaintext; any failure is an integrity refusal.
function openJwe(jwe, d, kid, what) {
  const bad = detail => refuse('integrity', `${what}:${detail}`)
  if (!isMap(jwe)) bad('jwe-shape')
  const protectedText = jwe.get('protected')
  const prot = protectedObject(protectedText)
  if (!prot) bad('protected')
  if (prot.enc !== 'A256GCM') bad('enc')
  const iv = b64uCanonical(jwe.get('iv')), tag = b64uCanonical(jwe.get('tag')), ciphertext = b64uCanonical(jwe.get('ciphertext'))
  if (!iv || iv.length !== 12 || !tag || tag.length !== 16 || !ciphertext) bad('members')
  const shared = jwe.has('unprotected') ? plain(jwe.get('unprotected')) : {}
  for (const r of jwe.get('recipients')) {
    if (!isMap(r)) continue
    const header = plain(r.get('header') ?? new Map())
    const union = { ...prot, ...shared, ...header }
    if (union.alg !== ECDH_ALG || union.kid !== kid) continue
    try {
      const epk = jwkPoint(union.epk)
      if (!epk) bad('epk')
      const z = ecdhX(P256, d, epk)
      const ek = b64uCanonical(r.get('encrypted_key'))
      if (!ek || ek.length !== 40) bad('encrypted_key')
      const cek = aesKwUnwrap(concatKdf(z, ECDH_ALG), ek)
      return gcmOpen(cek, iv, utf8(protectedText), ciphertext, tag)
    } catch (error) {
      if (error instanceof Refusal) throw error
      bad('decrypt')
    }
  }
  return bad('no-slot')
}

// Opens a JWE through its A256GCMKW slot with key `kek` (the convergent route of ENV §5.2, §9).
export function openConvergent(jwe, kek) {
  const prot = protectedObject(jwe.get('protected'))
  for (const r of jwe.get('recipients')) {
    const header = plain(r.get('header') ?? new Map())
    if (header.alg !== GCMKW_ALG) continue
    const cek = gcmOpen(kek, b64uCanonical(header.iv), null, b64uCanonical(r.get('encrypted_key')), b64uCanonical(header.tag))
    return { prot, plaintext: gcmOpen(cek, b64uCanonical(jwe.get('iv')), utf8(jwe.get('protected')), b64uCanonical(jwe.get('ciphertext')), b64uCanonical(jwe.get('tag'))) }
  }
  return null
}

// ---- ES256 (ENV §8.2, §8.3, §16; KEYS §1.8.3) ---------------------------------------------

function es256Verify(kidHex, message, signature) {
  if (!isText(kidHex) || !/^[0-9a-f]{66}$/.test(kidHex)) return false
  let point
  try { point = decodePoint(P256, Buffer.from(kidHex, 'hex')) } catch { return false }
  if (signature.length !== 64) return false
  const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64u(int32(point.x)), y: b64u(int32(point.y)) } })
  return cryptoVerify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature)
}

// ENV §8.3: rebuild {hdr, au, pr} under the current profile, then once under the superseded
// integer shape; fail closed. Returns the verified signatures with the shape each verified on.
export function verifySignatures(sigs, hdr, au, pr) {
  if (!isMap(sigs)) refuse('signature', 'sigs-shape')
  if (sigs.get('payload') !== '') refuse('signature', 'payload-not-empty')
  const list = sigs.get('signatures')
  if (!Array.isArray(list)) refuse('signature', 'signatures-shape')
  if (list.length === 0) refuse('signature', 'empty-signature-list')
  const signed = new Map([['hdr', hdr], ['au', au], ['pr', pr]])
  const candidates = [['current', () => cborEncode(signed)], ['superseded', () => encodeSuperseded(signed)]]
  for (const [shape, build] of candidates) {
    const payload = b64u(build())
    const verified = []
    for (const entry of list) {
      if (!isMap(entry)) continue
      const prot = protectedObject(entry.get('protected'))
      const signature = b64uCanonical(entry.get('signature'))
      if (!prot || prot.alg !== 'ES256' || !signature) continue
      if (es256Verify(prot.kid, utf8(`${entry.get('protected')}.${payload}`), signature)) verified.push({ kid: prot.kid, shape, signature })
    }
    if (verified.length > 0) return verified
  }
  return refuse('signature', 'no-signature-verifies')
}

// ---- values and slots -----------------------------------------------------------------------

export function toJson(value) {
  if (value instanceof Uint8Array) return { $bytes: hex(value) }
  if (isMap(value)) {
    const out = {}
    for (const [k, v] of value) { if (!isText(k)) throw new Error('non-text map key in a projected value'); out[k] = toJson(v) }
    return Object.fromEntries(Object.keys(out).sort().map(k => [k, out[k]]))
  }
  if (Array.isArray(value)) return value.map(toJson)
  return value
}
const ALLOWED_SCHEMES = ['overlay:', 's3:', 'gs:', 'file:', 'https:']

// ENV §7 rules 1-4, checked before any variant dispatch (ENV §14 steps 3, 9, 10).
function markerRules(slot) {
  if (!slot.has('u')) return false
  for (const m of ['v', 'jwe', 'im', 'je']) if (slot.has(m)) refuse('structure', 'marker-with-value') // rule 2
  if (slot.get('u') !== true) refuse('structure', 'marker-not-true') // rule 3
  if (slot.size !== 2) refuse('structure', 'marker-members') // rule 4: exactly n and u
  return true
}
function checkManifest(im) {
  if (!isMap(im) || im.size !== 3 || !isBytes(im.get('sha'), 32) || !isText(im.get('u')) || !isUint(im.get('sz'))) refuse('integrity', 'manifest-shape') // ENV-FP §3
  let scheme
  try { scheme = new URL(im.get('u')).protocol } catch { refuse('integrity', 'manifest-uri') }
  if (!ALLOWED_SCHEMES.includes(scheme)) refuse('integrity', 'uri-scheme') // ENV-FP §4
  return scheme
}
// Public and audit slots: value, unset or an externalised value. The laboratory reader has no
// store and no overlay resolver wired, so an externalised value is `unavailable` on an
// external scheme (ENV-FP §7.3) and an integrity refusal on overlay:// (ENV-FP §7.2).
function plainSlot(slot) {
  if (!isMap(slot) || !isText(slot.get('n'))) refuse('structure', 'slot-shape')
  if (markerRules(slot)) return { n: slot.get('n'), state: 'unset' }
  if (slot.has('v') && (slot.has('im') || slot.has('jwe') || slot.has('je'))) refuse('structure', 'slot-mixes-members') // ENV §8.1
  if (slot.has('v')) return { n: slot.get('n'), state: 'value', value: slot.get('v') }
  if (slot.has('im')) {
    if (checkManifest(slot.get('im')) === 'overlay:') refuse('integrity', 'overlay-could-not-ask')
    return { n: slot.get('n'), state: 'unavailable' }
  }
  return refuse('structure', 'slot-without-value') // ENV §7 rule 1
}
function slotNames(slots, where) {
  const names = new Set()
  for (const s of slots) {
    if (!isMap(s) || !isText(s.get('n'))) refuse('structure', `${where}-slot-shape`)
    if (names.has(s.get('n'))) refuse('structure', `duplicate-${where}-slot`) // ENV §8.1
    names.add(s.get('n'))
  }
}

function checkHeader(hdr) {
  const need = (ok, what) => { if (!ok) refuse('structure', `hdr-${what}`) }
  need(isMap(hdr), 'shape')
  need(isText(hdr.get('aid')), 'aid'); need(isUint(hdr.get('ep')), 'ep'); need(isText(hdr.get('f')), 'f')
  need(isUint(hdr.get('mv')), 'mv'); need(isUint(hdr.get('tm')), 'tm'); need(isBytes(hdr.get('pk'), 33), 'pk')
  need(typeof hdr.get('ds') === 'boolean', 'ds')
  if (!['root', 'delegate'].includes(hdr.get('pks'))) refuse('structure', 'pks') // ENV §6.1
  const dref = hdr.has('dref') ? hdr.get('dref') : []
  need(Array.isArray(dref) && dref.every(x => isBytes(x, 16)), 'dref')
  const fields = hdr.get('fields')
  need(Array.isArray(fields) && fields.length > 0, 'fields')
  const seen = new Set()
  for (const d of fields) {
    need(isMap(d) && isText(d.get('n')), 'descriptor')
    if (!['pu', 'au', 'pr'].includes(d.get('sn'))) refuse('structure', 'sn')
    if (!['ch', 'ov', 'ex'].includes(d.get('pl'))) refuse('structure', 'pl') // ENV §6.1
    if (d.has('cv')) {
      if (d.get('cv') !== true) refuse('structure', 'cv-not-true') // ENV §6.1 rule 1, rule 4
      if (d.get('sn') !== 'pr') refuse('structure', 'cv-not-private') // rule 2
    }
    if (seen.has(d.get('n'))) refuse('structure', 'duplicate-field-name') // ENV §6.1
    seen.add(d.get('n'))
  }
  return { fields, dref }
}

// ENV §6.1 rules 5 and 6: convergent material present, conjunctively, at both layers.
function hasConvergentMaterial(jwe) {
  if (!isMap(jwe)) return false
  const prot = protectedObject(jwe.get('protected'))
  const slot = (jwe.get('recipients') ?? []).some(r => isMap(r) && plain(r.get('header') ?? new Map())?.alg === GCMKW_ALG)
  return Boolean(prot && slot && Number.isSafeInteger(prot.iter) && prot.iter >= MIN_ITERATIONS && 'salt' in prot && prot.salt !== '' && prot.salt !== null)
}

// ---- the decode flow (ENV §14) --------------------------------------------------------------

export function readEnvelope(profile, request) {
  const ctx = { tier: 'nothing', aid: null }
  try {
    return readInner(profile, request, ctx)
  } catch (error) {
    if (!(error instanceof Refusal)) throw error
    return { tier: ctx.tier, verdict: 'refused', refusal: { class: error.cls, detail: error.detail }, aid: ctx.aid, fields: [] }
  }
}

function readInner(profile, request, ctx) {
  const reader = splitRoot(profile, Buffer.from(request.reader.rootIkm, 'hex'))
  const counterparty = request.as === 'writer' ? reader.R : Buffer.from(request.writer.R, 'hex')
  const { acct, rid } = request.writer
  let env
  try { env = cborDecode(Buffer.from(request.envelope, 'hex')) } catch (error) {
    if (error instanceof CborDetError) refuse('format', `envelope-cbor:${error.code}`)
    throw error
  }
  // ENV §2; ENV §14 steps 1-2. These format checks are exactly the keyless ANC §11.1 admission
  // gate, which ANC §11.1 makes the reader's own pre-unwrap gate: a map, the profile's `proto`,
  // a `pu` array and an outer JWE with ciphertext, IV and tag. Other members are not judged here.
  if (!isMap(env)) refuse('format', 'envelope-shape')
  if (env.get('proto') !== profile.formatIdentifier.value) refuse('format', 'proto')
  const pu = env.get('pu'), outer = env.get('outer')
  if (!Array.isArray(pu)) refuse('format', 'pu')
  if (!isMap(outer) || !['iv', 'ciphertext', 'tag'].every(m => isText(outer.get(m)))) refuse('format', 'outer-shape')

  // ENV §14 step 3: public slots, marker rules first.
  slotNames(pu, 'pu')
  const publicSlots = pu.map(plainSlot)

  // ENV §5.3: the protected-header aid must be present and text.
  const prot = protectedObject(outer.get('protected'))
  if (!prot || !isText(prot.aid)) refuse('integrity', 'protected-aid')
  ctx.aid = prot.aid

  // ENV §14 step 4(b): the reader's one candidate key, from the protected aid (ENV §8.6).
  const candidate = ownChild(reader.p256Seed, counterparty, outerIdentifier(profile, acct, rid, prot.aid))
  const candidateKid = hex(candidate.pub)
  const outerRecipients = Array.isArray(outer.get('recipients')) ? outer.get('recipients') : []
  const mine = outerRecipients.some(r => isMap(r) && isMap(r.get('header')) && r.get('header').get('kid') === candidateKid && r.get('header').get('alg') === ECDH_ALG)
  if (!mine) {
    return { tier: 'nothing', verdict: 'accepted', aid: prot.aid, fields: publicSlots.map(s => projectField(s.n, 'pu', s)) }
  }
  const auditBytes = openJwe(outer, candidate.d, candidateKid, 'outer')
  ctx.tier = 'audit'

  // ENV §6, §14 step 5.
  let audit
  try { audit = cborDecode(auditBytes) } catch (error) {
    if (error instanceof CborDetError) refuse('decode', `audit-cbor:${error.code}`)
    throw error
  }
  if (!isMap(audit)) refuse('structure', 'audit-shape')
  for (const k of audit.keys()) if (!['hdr', 'sigs', 'au', 'pr'].includes(k)) refuse('structure', 'audit-member')
  for (const k of ['hdr', 'sigs', 'au', 'pr']) if (!audit.has(k)) refuse('structure', `audit-missing-${k}`)
  const hdr = audit.get('hdr'), au = audit.get('au'), pr = audit.get('pr')
  if (!isMap(hdr)) refuse('structure', 'hdr-shape')
  // ENV §5.3, §14 step 5a.
  if (hdr.get('aid') !== prot.aid) refuse('integrity', 'aid-mismatch')
  // ENV §8.3, §14 steps 6-8.
  const verified = verifySignatures(audit.get('sigs'), hdr, au, pr)

  // ENV §6.1, then the KEYS §2.7.1 and §2.7.2 signer binding that needs no grant.
  const { fields, dref } = checkHeader(hdr)
  const pkHex = hex(hdr.get('pk'))
  if (hdr.get('pks') === 'root') {
    if (dref.length > 0) refuse('delegation-invalid', 'mixed-scope')
    if (verified[0].kid !== pkHex) refuse('root-pk-mismatch', 'pk-not-signer')
    if (request.as === 'writer') {
      const expected = hex(ownChild(reader.p256Seed, reader.R, signIdentifier(profile, acct, rid, hdr.get('aid'))).pub)
      if (verified[0].kid !== expected) refuse('root-pk-mismatch', 'kid-not-derived')
    }
  } else {
    if (dref.length !== 1) refuse('delegation-invalid', 'bad-dref-length')
    if (verified.length !== 1 || verified[0].kid !== pkHex) refuse('delegation-invalid', 'signer-binding')
  }

  // Descriptor-to-slot cross-check (ENV §6.1, §8.1).
  if (!Array.isArray(au) || !Array.isArray(pr)) refuse('structure', 'slot-arrays')
  slotNames(au, 'au'); slotNames(pr, 'pr')
  const descriptors = new Map(fields.map(d => [d.get('n'), d]))
  const placed = new Map()
  for (const [array, sn] of [[pu, 'pu'], [au, 'au'], [pr, 'pr']]) {
    for (const s of array) {
      const d = descriptors.get(s.get('n'))
      if (!d) refuse('structure', 'undeclared-slot') // ENV §8.1
      if (d.get('sn') !== sn) refuse('structure', 'slot-sensitivity')
      if (s.has('u') && d.get('pl') !== 'ch') refuse('structure', 'marker-not-in-record') // ENV §7 rule 3
      placed.set(s.get('n'), s)
    }
  }
  for (const d of fields) if (!placed.has(d.get('n'))) refuse('structure', 'descriptor-without-slot')

  // ENV §6.1 rules 5-9, after signature verification (rule 7).
  const cvDeclared = fields.filter(d => d.get('cv') === true)
  for (const d of cvDeclared) {
    const s = placed.get(d.get('n'))
    if (s.has('u')) continue // rule 9
    if (!hasConvergentMaterial(s.get('jwe') ?? s.get('je'))) refuse('structure', 'cv-backing-field')
  }
  if (cvDeclared.length > 0 && !hasConvergentMaterial(outer)) refuse('structure', 'cv-backing-outer')

  // ENV §14 steps 9-10.
  const values = new Map(publicSlots.map(s => [s.n, s]))
  for (const s of au) values.set(s.get('n'), plainSlot(s))
  for (const s of pr) values.set(s.get('n'), privateSlot(profile, s, descriptors.get(s.get('n')), { reader, counterparty, acct, rid, aid: hdr.get('aid') }))

  // ENV §14 step 11: one entry per descriptor, in declared order.
  return {
    tier: 'audit',
    verdict: 'accepted',
    aid: prot.aid,
    hdr: { f: hdr.get('f'), mv: hdr.get('mv'), ep: hdr.get('ep'), tm: hdr.get('tm'), pks: hdr.get('pks'), pk: pkHex, dref: dref.map(hex) },
    fields: fields.map(d => projectField(d.get('n'), d.get('sn'), values.get(d.get('n')))),
    signature: { kid: verified[0].kid, shape: verified[0].shape }
  }
}

function projectField(n, sn, slot) {
  const out = { n, sn, state: slot.state }
  if (slot.state === 'value') {
    out.value = toJson(slot.value)
    for (const k of ['filename', 'mediaType', 'meta']) if (slot[k] !== undefined && slot[k] !== null) out[k] = toJson(slot[k])
  }
  return out
}

function privateSlot(profile, slot, descriptor, keys) {
  const n = slot.get('n')
  if (markerRules(slot)) return { n, state: 'unset' } // never reaches the resolver (ENV §7.1)
  const inRecord = slot.has('jwe')
  if (inRecord && (slot.has('v') || slot.has('im') || slot.has('je'))) refuse('structure', 'slot-mixes-members') // ENV §8.1
  if (!inRecord && !(slot.has('je') && slot.has('im'))) refuse('structure', 'private-slot-shape')
  if (inRecord !== (descriptor.get('pl') === 'ch')) refuse('structure', 'slot-placement')
  const jwe = inRecord ? slot.get('jwe') : slot.get('je')
  if (!inRecord) checkManifest(slot.get('im'))
  if (!isMap(jwe) || !Array.isArray(jwe.get('recipients'))) refuse('integrity', 'slot-validation:jwe-shape')
  // ENV §9.1 rule 2: a JWE with no recipient list is refused, never redacted.
  if (jwe.get('recipients').length === 0) refuse('integrity', 'recipient-less')
  // The resolver decides on the identity recipient identifiers (never the convergent slot's).
  const kids = jwe.get('recipients').map(r => (isMap(r) && isMap(r.get('header')) && r.get('header').get('alg') === ECDH_ALG) ? r.get('header').get('kid') : null).filter(isText)
  const child = ownChild(keys.reader.p256Seed, keys.counterparty, fieldIdentifier(profile, keys.acct, keys.rid, keys.aid, n))
  const kid = hex(child.pub)
  if (!kids.includes(kid)) {
    validateForDecline(jwe, inRecord)
    return { n, state: 'redacted' }
  }
  if (!inRecord) return { n, state: 'unavailable' } // no store configured (ENV-FP §7.3)
  const compressed = openJwe(jwe, child.d, kid, `field ${n}`)
  let tuple
  try {
    tuple = cborDecode(decodeAlone(compressed).output)
  } catch (error) {
    if (error instanceof LzmaError) refuse('decode', `lzma:${error.code}`)
    if (error instanceof CborDetError) refuse('decode', `tuple-cbor:${error.code}`)
    throw error
  }
  if (!Array.isArray(tuple) || tuple.length < 1 || tuple.length > 4) refuse('decode', 'tuple-shape')
  const [value, filename, mediaType, meta] = tuple
  return { n, state: 'value', value, filename, mediaType, meta, compressed }
}

// ---- writer-side input rules (ENV §6.1, §7.1, §9, §9.1, §13; KEYS §1.6.2) ----------------------

export function writeRefusal(request) {
  const seen = new Set()
  const recipientsOf = name => Object.entries(request.fieldRecipients ?? {}).find(([k]) => k.normalize('NFC') === name)?.[1] ?? []
  for (const f of request.record.fields) {
    const name = f.n.normalize('NFC')
    const length = utf8(name).length
    if (length < 1 || length > 256) return 'field-name-length'
    if (name.includes('/')) return 'field-name-separator'
    if (seen.has(name)) return 'duplicate-field-name'
    seen.add(name)
    if ('cv' in f && f.cv !== true) return 'cv-not-true'
    if ('cv' in f && f.sn !== 'pr') return 'cv-not-private'
    if (f.blind === true) {
      if (f.sn !== 'pr') return 'blind-not-private'
      if ('cv' in f) return 'blind-cv'
      if (recipientsOf(name).length === 0) return 'blind-without-recipient'
    }
    if (f.sn === 'pr' && !('value' in f)) {
      if (f.pl !== 'ch') return 'unset-externalised-private'
      if ('filename' in f || 'mediaType' in f || 'meta' in f) return 'unset-with-metadata'
    }
    if (f.sn === 'pr' && 'value' in f && (f.cv === true ? 1 : 0) + (f.blind === true ? 0 : 1) + recipientsOf(name).length === 0) return 'unopenable-slot'
  }
  return null
}

// ---- ENV §4 ---------------------------------------------------------------------------------

export function secrets(data, iterations = MIN_ITERATIONS) {
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS) return null
  const hash = sha256(data)
  const key = pbkdf2Sync(data, hash, iterations, 64, 'sha256')
  const s1 = key.subarray(0, 32), s2 = key.subarray(32)
  return { hash, s1, s2, cek: createHmac('sha256', s2).update(s1).digest() }
}

// ---- write-direction checks ---------------------------------------------------------------

function fieldTupleBytes(field) {
  const fromJson = v => {
    if (v === null || typeof v !== 'object') return v
    if (Array.isArray(v)) return v.map(fromJson)
    const keys = Object.keys(v)
    if (keys.length === 1 && keys[0] === '$bytes') return Uint8Array.from(Buffer.from(v.$bytes, 'hex'))
    return new Map(keys.map(k => [k, fromJson(v[k])]))
  }
  const rest = ['filename', 'mediaType', 'meta']
  const last = Math.max(-1, ...rest.map((k, i) => (k in field ? i : -1)))
  const tuple = [fromJson(field.value)]
  for (let i = 0; i <= last; i++) tuple.push(rest[i] in field ? fromJson(field[rest[i]]) : null)
  return cborEncode(tuple)
}

// Checks a writer's envelope for one write case. Each check carries its tag; only `required`
// checks can fail an implementation. Checks marked `random` apply only when the writer used
// the case's frozen random values.
export function checkWrite(profile, kase, envelopeHex) {
  const results = []
  const check = (name, tag, ok, detail = '', random = false) => results.push({ check: name, tag, ok: Boolean(ok), detail, ...(random ? { random: true } : {}) })
  try {
    checkWriteInner(profile, kase, envelopeHex, check)
  } catch (error) {
    // An envelope the checks cannot walk (undecodable, or no slot the writer can open) fails here.
    check('envelope-readable', 'required', false, error instanceof Refusal || error instanceof CborDetError || error instanceof TypeError || error instanceof EcError ? error.message : String(error))
  }
  return results
}

function checkWriteInner(profile, kase, envelopeHex, check) {
  const req = kase.request
  const bytes = Buffer.from(envelopeHex, 'hex')
  const env = cborDecode(bytes)
  check('envelope-deterministic', 'required', isDeterministic(bytes), 'ENV §3')
  check('envelope-members', 'required', isMap(env) && [...env.keys()].sort().join() === 'outer,proto,pu' && env.get('proto') === profile.formatIdentifier.value, 'ENV §2')
  const writer = splitRoot(profile, Buffer.from(req.writer.rootIkm, 'hex'))
  const { acct, rid } = req.writer
  const aid = req.record.aid
  const outer = env.get('outer')
  const prot = protectedObject(outer.get('protected'))
  const fields = req.record.fields.map(f => ({ ...f, n: f.n.normalize('NFC') }))
  const convergent = fields.some(f => f.sn === 'pr' && f.cv === true)
  const protKeys = Object.keys(prot).sort().join()
  check('outer-protected-members', 'required', protKeys === (convergent ? 'aid,enc,iter,proto,salt' : 'aid,enc,proto') && prot.enc === 'A256GCM' && prot.proto === profile.formatIdentifier.value && prot.aid === aid, `ENV §5.2, §11: ${protKeys}`)
  // Expected identity recipients: the writer self-recipient, then the audit recipients (ENV §5.2, §8.6).
  const oid = outerIdentifier(profile, acct, rid, aid)
  const expectedOuter = [hex(ownChild(writer.p256Seed, writer.R, oid).pub), ...req.auditRecipients.map(r => hex(theirChild(writer.p256Seed, Buffer.from(r, 'hex'), oid)))]
  const recips = outer.get('recipients').map(r => plain(r.get('header')))
  const identity = recips.filter(h => h.alg === ECDH_ALG)
  check('outer-self-recipient', 'required', identity.some(h => h.kid === expectedOuter[0]), 'ENV §5.2')
  check('outer-recipient-kids', 'required', [...identity.map(h => h.kid)].sort().join() === [...expectedOuter].sort().join(), 'ENV §8.6')
  check('outer-recipient-order', 'labChoice', identity.map(h => h.kid).join() === expectedOuter.join(), 'self first')
  check('outer-epk-per-recipient', 'required', identity.every(h => jwkPoint(h.epk) && Object.keys(h).sort().join() === 'alg,epk,kid'), 'ENV §11')
  check('outer-convergent-slot', 'required', recips.some(h => h.alg === GCMKW_ALG) === convergent, 'ENV §5.2')
  // Open as the writer: through the self-recipient, which a writer holding only its root needs.
  const self = ownChild(writer.p256Seed, writer.R, oid)
  if (!identity.some(h => h.kid === hex(self.pub))) return
  const auditBytes = openJwe(outer, self.d, hex(self.pub), 'outer')
  check('audit-deterministic', 'required', isDeterministic(auditBytes), 'ENV §3')
  const audit = cborDecode(auditBytes)
  check('audit-members', 'required', [...audit.keys()].sort().join() === 'au,hdr,pr,sigs', 'ENV §6')
  const hdr = audit.get('hdr')
  const signKid = hex(ownChild(writer.p256Seed, writer.R, signIdentifier(profile, acct, rid, aid)).pub)
  const wantFields = fields.map(f => [f.n, f.sn, f.pl, f.cv === true].join('|')).join(';')
  const gotFields = (hdr.get('fields') ?? []).map(d => [d.get('n'), d.get('sn'), d.get('pl'), d.get('cv') === true].join('|')).join(';')
  check('hdr-values', 'required', hdr.get('aid') === aid && hdr.get('ep') === req.writer.ep && hdr.get('f') === req.record.f && hdr.get('mv') === req.record.mv && hdr.get('tm') === req.record.tm, 'ENV §6.1')
  check('hdr-fields', 'required', gotFields === wantFields, 'ENV §6.1, §13 step 5')
  check('hdr-signer', 'required', hex(hdr.get('pk')) === signKid && hdr.get('pks') === 'root' && hdr.get('ds') === false && Array.isArray(hdr.get('dref')) && hdr.get('dref').length === 0, 'ENV §6.1; KEYS §2.7.1')
  const sigs = audit.get('sigs')
  let verified = null
  try { verified = verifySignatures(sigs, hdr, audit.get('au'), audit.get('pr')) } catch (error) { if (!(error instanceof Refusal)) throw error }
  const list = sigs.get('signatures')
  const sigProt = list.length === 1 ? protectedObject(list[0].get('protected')) : null
  check('signature-shape', 'required', sigs.get('payload') === '' && list.length === 1 && sigProt && Object.keys(sigProt).sort().join() === 'alg,kid' && sigProt.alg === 'ES256' && b64uCanonical(list[0].get('signature'))?.length === 64, 'ENV §8.2')
  check('signature-kid', 'required', sigProt?.kid === signKid, 'ENV §8.5')
  check('signature-verifies-current', 'required', verified && verified[0].shape === 'current', 'ENV §8.3')
  if (verified) { const s = toInt(verified[0].signature.subarray(32)); check('signature-low-s', 'labChoice', s <= P256.n / 2n, 'KEYS §1.8.3 SHOULD') }
  if (convergent) {
    const rec = secrets(auditBytes)
    let opened = null
    try { opened = openConvergent(outer, rec.s1) } catch { opened = null }
    check('outer-convergent-opens', 'required', opened && Buffer.compare(opened.plaintext, auditBytes) === 0, 'ENV §5.2, §13 steps 9-10: key s1 of the audit layer')
    check('outer-convergent-header', 'required', prot.iter === MIN_ITERATIONS && isText(prot.salt) && prot.salt.length > 0, 'ENV §5.2, §6.1 rule 6')
    check('outer-convergent-salt', 'labChoice', prot.salt === b64u(rec.hash), 'salt as base64url of SHA-256 (shape unconstrained, ENV §6.1 rule 6)')
  }
  // Private fields.
  const prSlots = new Map(audit.get('pr').map(s => [s.get('n'), s]))
  for (const f of fields.filter(x => x.sn === 'pr' && 'value' in x)) {
    const s = prSlots.get(f.n)
    const jwe = s?.get('jwe')
    if (!jwe) { check(`field-${f.n}-slot`, 'required', false, 'ENV §8.1'); continue }
    const fprot = protectedObject(jwe.get('protected'))
    check(`field-${f.n}-protected`, 'required', Object.keys(fprot).sort().join() === (f.cv === true ? 'enc,iter,salt' : 'enc') && fprot.enc === 'A256GCM', 'ENV §9')
    const fid = fieldIdentifier(profile, acct, rid, aid, f.n)
    const ext = (Object.entries(req.fieldRecipients ?? {}).find(([k]) => k.normalize('NFC') === f.n)?.[1] ?? []).map(r => hex(theirChild(writer.p256Seed, Buffer.from(r, 'hex'), fid)))
    const selfChild = ownChild(writer.p256Seed, writer.R, fid)
    const expected = [...(f.blind === true ? [] : [hex(selfChild.pub)]), ...ext]
    const fh = jwe.get('recipients').map(r => plain(r.get('header')))
    check(`field-${f.n}-kids`, 'required', fh.filter(h => h.alg === ECDH_ALG).map(h => h.kid).join() === expected.join(), 'ENV §8.6, §9 (self-recipient first), §9.1')
    check(`field-${f.n}-epk-per-recipient`, 'required', fh.filter(h => h.alg === ECDH_ALG).every(h => jwkPoint(h.epk)), 'ENV §9')
    check(`field-${f.n}-convergent-slot`, 'required', fh.some(h => h.alg === GCMKW_ALG) === (f.cv === true), 'ENV §9')
    const tupleBytes = fieldTupleBytes(f)
    if (f.cv === true) {
      const fs = secrets(tupleBytes)
      let opened = null
      try { opened = openConvergent(jwe, fs.cek) } catch { opened = null }
      check(`field-${f.n}-convergent-opens`, 'required', Boolean(opened), 'ENV §4, §9: key HMAC(s2, s1) of the field plaintext')
    }
    if (f.blind !== true) {
      const compressed = openJwe(jwe, selfChild.d, hex(selfChild.pub), `field ${f.n}`)
      let lz = null
      try { lz = decodeAlone(compressed) } catch (error) { if (!(error instanceof LzmaError)) throw error }
      check(`field-${f.n}-lzma-no-marker`, 'required', lz && lz.marker === false, 'ENV §9: end-of-stream marker disabled')
      check(`field-${f.n}-lzma-alone-size`, 'labChoice', lz && lz.declaredSize === tupleBytes.length, 'laboratory reading: alone header with the size')
      check(`field-${f.n}-plaintext`, 'required', lz && Buffer.compare(Buffer.from(lz.output), tupleBytes) === 0, 'ENV §9: deterministicEncode([value, filename?, mediaType?, meta?])')
    }
  }
  // Frozen randomness: the key-management bytes a writer given the case's values reproduces.
  const det = kase.expect?.deterministic
  if (det) {
    check('outer-iv', 'required', outer.get('iv') === det.outer.iv, 'frozen IV', true)
    const ek = outer.get('recipients').map(r => r.get('encrypted_key')).join()
    check('outer-encrypted-keys', 'required', ek === det.outer.encryptedKeys.join(), 'frozen CEK and ephemeral keys', true)
    for (const [name, want] of Object.entries(det.fields ?? {})) {
      const jwe = prSlots.get(name)?.get('jwe')
      check(`field-${name}-encrypted-keys`, 'required', jwe && jwe.get('iv') === want.iv && jwe.get('recipients').map(r => r.get('encrypted_key')).join() === want.encryptedKeys.join(), 'frozen CEK, IV and ephemeral keys', true)
    }
  }
}

// ---- cases ----------------------------------------------------------------------------------

// Projections are compared in full when the record is accepted; a refusal is compared by
// verdict, and by class when the case tags the class `required`.
export function compareProjection(expected, actual, classTag = 'required') {
  if (expected.verdict !== actual.verdict) return `verdict ${actual.verdict}, expected ${expected.verdict}`
  if (expected.verdict === 'refused') {
    if (classTag === 'required' && expected.refusal.class !== actual.refusal.class) return `refusal class ${actual.refusal.class}, expected ${expected.refusal.class}`
    return null
  }
  const a = JSON.stringify(actual), e = JSON.stringify(expected)
  return a === e ? null : `projection differs: ${a} vs ${e}`
}

export function runCase(profile, kase) {
  const req = kase.request
  if (req.op === 'read') {
    const actual = readEnvelope(profile, req)
    const diff = compareProjection(kase.expect, actual, kase.classTag ?? 'required')
    return { ok: diff === null, actual, failures: diff ? [diff] : [] }
  }
  if (req.op === 'write') {
    const refusal = writeRefusal(req)
    if (kase.expect.refusal) {
      const ok = refusal !== null && refusal === kase.expect.refusal.detail
      return { ok, actual: { refusal }, failures: ok ? [] : [`writer rule ${refusal}, expected ${kase.expect.refusal.detail}`] }
    }
    if (refusal !== null) return { ok: false, actual: { refusal }, failures: [`writer rule refused ${refusal}`] }
    const results = checkWrite(profile, kase, kase.expect.envelope)
    const failures = results.filter(r => !r.ok).map(r => `${r.check} (${r.tag}): ${r.detail}`)
    return { ok: failures.length === 0, actual: { checks: results.length }, failures }
  }
  if (req.op === 'secrets') {
    const s = secrets(Buffer.from(req.data, 'hex'), req.iterations)
    const actual = s === null ? { refusal: { class: 'input', detail: 'iterations-below-floor' } } : { hash: hex(s.hash), s1: hex(s.s1), s2: hex(s.s2), cek: hex(s.cek) }
    const ok = JSON.stringify(actual) === JSON.stringify(kase.expect)
    return { ok, actual, failures: ok ? [] : ['secrets differ'] }
  }
  throw new Error(`unknown op ${req.op}`)
}

export { EcError }
