// LAB_SELF_TEST_ONLY oracle for VA-KEY: the KEYS §1.12 known-answer tests under the laboratory
// deployment profile, as the driver contract's split, derive, symmetric, validate, offset and
// profile operations. Node.js built-ins only: HKDF and HMAC by node:crypto, curve arithmetic by
// src/sdx/ec-p256.mjs (OpenSSL scalar multiplication). It imports no generator code.
import fs from 'node:fs'
import { createHmac, hkdfSync } from 'node:crypto'
import { CURVES, addPoints, decodePoint, ecdhPoint, encodePoint, int32, mulBase, toInt } from './ec-p256.mjs'

const utf8 = text => Buffer.from(text, 'utf8')
const hex = bytes => Buffer.from(bytes).toString('hex')
class KeyRefusal extends Error { constructor(detail) { super(detail); this.detail = detail } }
const refuse = detail => { throw new KeyRefusal(detail) }
const curveOf = name => { if (!CURVES[name]) refuse('curve'); return CURVES[name] }

// KEYS §1.3: space-form namespaces.
export const spaceForm = name => typeof name === 'string' && /^[a-z0-9 ]{5,280}$/.test(name) && !name.includes('  ') && !/(^| )protocol$/.test(name)

export function split(profile, ikm) {
  if (ikm.length !== 64) refuse('root-length') // KEYS §1.4.1
  const labels = profile.derivation.curveLabels
  const seed = label => Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), utf8(label), 32))
  const out = { secp256k1Seed: seed(labels.secp256k1), p256Seed: seed(labels.p256) }
  // KEYS §1.4.3: both seeds checked before either is returned; never clamped.
  if (toInt(out.secp256k1Seed) === 0n || toInt(out.secp256k1Seed) >= CURVES.secp256k1.n) refuse('seed-out-of-range')
  if (toInt(out.p256Seed) === 0n || toInt(out.p256Seed) >= CURVES.p256.n) refuse('seed-out-of-range')
  return out
}

// KEYS §1.8.2 scalar rejection, before any reduction.
export function checkOffset(curveName, hmac) {
  const h = toInt(hmac)
  if (h === 0n || h >= curveOf(curveName).n) refuse(`offset-out-of-range:${curveName}`)
  return h
}

// KEYS §1.6.1 under the profile: the five-level structure, the closed purpose set, the
// variants, no empty segment, at most 1033 bytes (KEYS §1.3) and field names of 1 to 256 bytes.
export function validateKeyPath(profile, keyPath) {
  const kw = profile.derivation.keyPath.keywords
  const purposes = profile.derivation.keyPath.purposes.map(p => p.purpose)
  if (utf8(keyPath).length < 1 || utf8(keyPath).length > 1033) return 'length'
  const s = keyPath.split('/')
  if (s.some(x => x.length === 0)) return 'segment'
  if (s.length % 2 !== 0) return 'structure'
  if (s[0] !== kw.level1) return 'keyword'
  if (s.length >= 4 && s[2] !== kw.level2) return 'keyword'
  if (s.length >= 6) {
    if (s[4] === kw.level3Session) return s.length === 6 ? null : 'structure'
    if (s[4] === kw.level3Delegation) return s.length === 8 && s[6] === kw.delegationActor ? null : 'structure'
    if (s[4] !== kw.level3) return 'keyword'
  }
  if (s.length === 8) {
    if (!purposes.includes(s[6])) return 'purpose'
    if (s[6] === 'field' && utf8(s[7]).length > 256) return 'field-name'
  }
  if (s.length > 8) return 'structure'
  return null
}

function namespaceOf(profile, namespace) {
  const ns = profile.derivation.namespaces
  const role = Object.keys(ns).find(r => ns[r] === namespace)
  if (!role) refuse('namespace') // KEYS §1.7: never derive under a namespace absent from the profile
  if (profile.derivation.namespaceUse?.[role]?.startsWith('Reserved')) refuse('namespace-reserved')
  return namespace
}

function deriveOne(profile, req) {
  const curve = curveOf(req.curve)
  const seeds = split(profile, Buffer.from(req.rootIkm, 'hex'))
  const seed = req.curve === 'p256' ? seeds.p256Seed : seeds.secp256k1Seed
  const keyPath = req.keyPath.normalize('NFC') // KEYS §1.6.2
  const bad = validateKeyPath(profile, keyPath)
  if (bad) refuse(`key-path:${bad}`)
  const identifier = `${profile.derivation.securityLevel}-${namespaceOf(profile, req.namespace)}-${keyPath}`
  const d = toInt(seed)
  const ownPub = encodePoint(curve, mulBase(curve, d))
  const counterparty = req.counterparty === 'self' ? ownPub : Buffer.from(req.counterparty, 'hex')
  const shared = encodePoint(curve, ecdhPoint(curve, d, counterparty))
  const h = checkOffset(req.curve, createHmac('sha256', shared).update(utf8(identifier)).digest())
  if (req.side === 'own') {
    const child = (d + h) % curve.n
    return { identifier, child, publicKey: encodePoint(curve, mulBase(curve, child)), privateKey: int32(child) }
  }
  return { identifier, publicKey: encodePoint(curve, addPoints(curve, mulBase(curve, h), decodePoint(curve, counterparty))) }
}

// KEYS §1.12 item 11 for a profile document.
export function profileFailures(profile) {
  const d = profile.derivation
  const failures = []
  const ns = d.namespaces
  for (const role of ['encryption', 'signing', 'delegation', 'transportAuthentication', 'rotation', 'handoff']) if (!spaceForm(ns[role])) failures.push(`namespace-grammar:${role}`)
  const names = Object.values(ns)
  if (new Set(names).size !== names.length) failures.push('namespaces-distinct')
  for (const curve of ['secp256k1', 'p256']) if (!/^[\x21-\x7e]+$/.test(d.curveLabels[curve] ?? '')) failures.push(`label:${curve}`)
  if (d.curveLabels.secp256k1 && d.curveLabels.secp256k1 === d.curveLabels.p256) failures.push('labels-distinct')
  for (const [k, w] of Object.entries(d.keyPath.keywords)) if (!w || w.includes('/')) failures.push(`keyword:${k}`)
  const purposes = d.keyPath.purposes.map(p => p.purpose)
  for (const p of purposes) if (!p || p.includes('/')) failures.push(`purpose:${p}`)
  if (new Set(purposes).size !== purposes.length) failures.push('purposes-distinct')
  if (!d.credentialType?.value) failures.push('credential-type')
  return failures
}

export function perform(profile, req) {
  try {
    switch (req.op) {
      case 'split': { const s = split(profile, Buffer.from(req.rootIkm, 'hex')); return { secp256k1Seed: hex(s.secp256k1Seed), p256Seed: hex(s.p256Seed) } }
      case 'derive': { const r = deriveOne(profile, req); return { identifier: r.identifier, publicKey: hex(r.publicKey), ...(req.side === 'own' ? { privateKey: hex(r.privateKey) } : {}) } }
      case 'symmetric': {
        // BRC-2: x of (own derived private key) times (the counterparty's derived public key).
        const own = deriveOne(profile, { ...req, side: 'own' })
        const theirs = deriveOne(profile, { ...req, side: 'counterparty' })
        const curve = curveOf(req.curve)
        return { identifier: own.identifier, key: hex(int32(ecdhPoint(curve, own.child, theirs.publicKey).x)) }
      }
      case 'validate': { const bad = validateKeyPath(profile, req.keyPath); return bad ? { verdict: 'refused', detail: bad } : { verdict: 'accepted' } }
      case 'offset': return { scalar: hex(int32(checkOffset(req.curve, Buffer.from(req.hmac, 'hex')))) }
      case 'profile': {
        const doc = typeof req.profile === 'string' ? JSON.parse(fs.readFileSync(new URL(`../../${req.profile}`, import.meta.url))) : req.profile.inline
        const failures = profileFailures(doc)
        return { verdict: failures.length ? 'nonconforming' : 'conforming', failures }
      }
      default: throw new Error(`unknown op ${req.op}`)
    }
  } catch (error) {
    if (error instanceof KeyRefusal) return { refusal: { class: 'key', detail: error.detail } }
    throw error
  }
}

export function runCase(profile, kase) {
  const actual = perform(profile, kase.request)
  return { ok: JSON.stringify(actual) === JSON.stringify(kase.expect), actual }
}
