import { createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, randomBytes, verify as verifySignature } from 'node:crypto'
import { CURVES, EcError, addPoints, decodePoint, ecdhPoint, ecdhX, encodePoint, int32, mod, modInverse, mulBase, toInt } from './ec-p256.mjs'
import { CheckError, deriveChildPrivateKey, invoiceNumber, offsetScalar, publicKeyFromPrivate, sharedSecretPoint } from './brc42.mjs'

// Independent checker and reference semantics for the `p sdx` BRC-98 module: a
// wallet that holds SDX accounts and serves both of their key trees. This file
// holds the module semantics and the checker of suite VC-P256; src/sdx/k1.mjs
// checks VC-SDX-K1 with the same semantics. It uses node:crypto (OpenSSL ECDH,
// HKDF, HMAC, AES key unwrap and AES-GCM), src/sdx/ec-p256.mjs for both curves,
// and the laboratory's secp256k1 oracle src/sdx/brc42.mjs for BRC-42. It imports
// no wallet, Toolbox, JOSE, CBOR or curve library, and nothing from any vector
// generator.
export { EcError }
export const P256 = CURVES.p256
export const SECP256K1 = CURVES.secp256k1
const SCHEME = 'p sdx '
const MAX_KEY_PATH_BYTES = 1033 // KEYS §1.3
export const ROLES = Object.freeze(['write', 'read', 'root', 'actor', 'session'])
export const ACCOUNT_ROLES = Object.freeze(['write', 'read', 'root'])
export const OPERATIONS = Object.freeze({
  open: 'encrypt', key: 'encrypt', peer: 'encrypt', sign: 'encrypt', decrypt: 'decrypt',
  k1key: 'encrypt', k1peer: 'encrypt', k1sign: 'encrypt'
})
// The curve each operation derives on; `open` returns the roots of both.
export const CURVE_OF = Object.freeze({ key: P256, peer: P256, sign: P256, decrypt: P256, k1key: SECP256K1, k1peer: SECP256K1, k1sign: SECP256K1 })
export const MEMBERS = Object.freeze({
  open: { required: ['acct'], optional: ['ep'] },
  key: { required: [], optional: ['path', 'peer', 'ep'] },
  peer: { required: ['path', 'peer'], optional: ['ep'] },
  sign: { required: ['path', 'msg'], optional: ['peer', 'ep'] },
  decrypt: { required: ['path', 'peer', 'jwe'], optional: ['ep'] },
  k1key: { required: [], optional: ['path', 'peer', 'ep'] },
  k1peer: { required: ['path', 'peer'], optional: ['ep'] },
  k1sign: { required: ['path', 'hash'], optional: ['peer', 'ep'] }
})
// CBOR major type of each member: text, unsigned integer, map, or (by default) bytes.
const MEMBER_TYPES = Object.freeze({ path: 'tstr', acct: 'tstr', ep: 'uint', jwe: 'map' })
export const memberType = name => MEMBER_TYPES[name] ?? 'bstr'
const PROTOCOL_METHODS = new Set(['getPublicKey', 'encrypt', 'decrypt', 'createHmac', 'verifyHmac', 'createSignature', 'verifySignature', 'revealSpecificKeyLinkage'])
const NAMED_METHODS = Object.freeze({
  createAction: args => [...(args.outputs ?? []).map(output => output.basket), ...(args.labels ?? [])],
  internalizeAction: args => [...(args.outputs ?? []).map(output => output.insertionRemittance?.basket), ...(args.labels ?? [])],
  listOutputs: args => [args.basket],
  listActions: args => args.labels ?? [],
  relinquishOutput: args => [args.basket]
})

const HEX = /^(?:[0-9a-f]{2})*$/
export function fromHex(text) {
  if (typeof text !== 'string' || !HEX.test(text)) throw new TypeError('lowercase even-length hex expected')
  return Buffer.from(text, 'hex')
}
const hex = bytes => Buffer.from(bytes).toString('hex')
const sha256 = bytes => createHash('sha256').update(bytes).digest()
const u32 = value => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes }
export const accountTag = acct => sha256(Buffer.from(acct, 'utf8')).subarray(0, 16).toString('hex')

// ---- KEYS §1.4: root split ---------------------------------------------------

const ORDERS = Object.freeze({ p256: P256.n, secp256k1: SECP256K1.n })
export const seedInRange = (curve, seed) => { const value = toInt(seed); return seed.length === 32 && value > 0n && value < ORDERS[curve] }
export function splitIkm(ikm, labels) {
  if (!(ikm instanceof Uint8Array) || ikm.length !== 64) throw new EcError('ikm-length')
  if (labels.secp256k1 === labels.p256) throw new EcError('profile-labels')
  const seed = label => Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(label, 'utf8'), 32))
  const secp256k1Seed = seed(labels.secp256k1), p256Seed = seed(labels.p256)
  // KEYS §1.4.3: both seeds are checked before either is returned; never clamped.
  for (const [curve, value, name] of [['secp256k1', secp256k1Seed, 'secp256k1'], ['p256', p256Seed, 'P-256']]) {
    if (!seedInRange(curve, value)) throw new EcError('ikm-unusable', name)
  }
  return { secp256k1Seed, p256Seed }
}
// One root as the module holds it: both seeds, as scalars, and both root public keys.
export function rootFromIkm(ikm, labels) {
  const { secp256k1Seed, p256Seed } = splitIkm(ikm, labels)
  const r = toInt(p256Seed), k = toInt(secp256k1Seed)
  return { ikm: Buffer.from(ikm), secp256k1Seed, p256Seed, r, k, R: encodePoint(P256, mulBase(P256, r)), K: encodePoint(SECP256K1, mulBase(SECP256K1, k)) }
}
// Draft §Canonical derivation step 1: a root derived inside the wallet from its own root.
export function walletDerivedIkm(walletRoot, derivation, keyID) {
  const d = deriveChildPrivateKey({ rootPrivateKey: walletRoot, protocolID: derivation.protocolID, keyID, counterparty: 'self' })
  return Buffer.from(hkdfSync('sha256', d, Buffer.from(derivation.salt, 'utf8'), Buffer.from(derivation.info, 'utf8'), derivation.length))
}

// ---- KEYS §1.8.2: child derivation on either curve ----------------------------------

export function checkOffset(hmac, curve = P256) {
  const h = toInt(hmac)
  if (hmac.length !== 32 || h === 0n || h >= curve.n) throw new EcError('scalar-rejected', curve.name)
  return h
}
export function offsetMaterial(own, counterparty, identifier, curve = P256) {
  if (typeof identifier !== 'string') throw new EcError('member-type', 'path')
  const sharedPoint = encodePoint(curve, ecdhPoint(curve, own, counterparty))
  return { sharedPoint, hmac: createHmac('sha256', sharedPoint).update(Buffer.from(identifier, 'utf8')).digest() }
}
// `inject` replaces the HMAC output, for offsets no search can find (KEYS §1.12 item 7).
export function ownChild(own, counterparty, identifier, curve = P256, inject) {
  const material = offsetMaterial(own, counterparty, identifier, curve)
  const h = checkOffset(inject ?? material.hmac, curve)
  const childPrivate = mod(own + h, curve.n)
  if (childPrivate === 0n) throw new EcError('child-zero', curve.name)
  return { ...material, h, childPrivate, publicKey: encodePoint(curve, mulBase(curve, childPrivate)) }
}
export function counterpartyChild(own, counterparty, identifier, curve = P256, inject) {
  const material = offsetMaterial(own, counterparty, identifier, curve)
  const h = checkOffset(inject ?? material.hmac, curve)
  const child = addPoints(curve, decodePoint(curve, counterparty), mulBase(curve, h))
  if (child === null) throw new EcError('point-infinity')
  return { ...material, h, publicKey: encodePoint(curve, child) }
}
// ---- ECDSA: RFC 6979 nonce, then low-S (KEYS §1.8.3), on either curve ---------------

function* rfc6979(d, digest, curve) {
  const mac = (key, ...parts) => createHmac('sha256', key).update(Buffer.concat(parts)).digest()
  const x = int32(d), h1 = int32(mod(toInt(digest), curve.n))
  let v = Buffer.alloc(32, 1), k = Buffer.alloc(32, 0)
  k = mac(k, v, Buffer.from([0]), x, h1); v = mac(k, v)
  k = mac(k, v, Buffer.from([1]), x, h1); v = mac(k, v)
  for (;;) {
    v = mac(k, v) // qlen = hlen = 256 bits on both curves: one HMAC block per candidate
    const candidate = toInt(v)
    if (candidate > 0n && candidate < curve.n) yield candidate
    k = mac(k, v, Buffer.from([0])); v = mac(k, v)
  }
}
// The RFC 6979 signature over a 32-byte digest, before any normalisation.
export function signDeterministic(d, digest, curve = P256) {
  const z = mod(toInt(digest), curve.n)
  for (const k of rfc6979(d, digest, curve)) {
    const r = mod(mulBase(curve, k).x, curve.n)
    if (r === 0n) continue
    const s = mod(modInverse(k, curve.n) * (z + r * d), curve.n)
    if (s !== 0n) return { r, s, k }
  }
}
export const lowS = (s, curve = P256) => s > curve.n / 2n ? curve.n - s : s
// The module's `sign` result: RFC 6979 over SHA-256(message), then low-S, as r || s.
export function es256Sign(d, message) {
  const { r, s } = signDeterministic(d, sha256(message))
  return Buffer.concat([int32(r), int32(lowS(s))])
}
// OpenSSL verification; it accepts either S, as KEYS §1.8.3 asks of verifiers.
export function es256Verify(publicKey, message, signature) {
  if (signature.length !== 64) return false
  const point = decodePoint(P256, publicKey)
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: int32(point.x).toString('base64url'), y: int32(point.y).toString('base64url') }, format: 'jwk' })
  return verifySignature('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature)
}
// DER (X.690) INTEGER pair, as BRC-100 createSignature returns it.
const derInteger = value => {
  let bytes = Buffer.from(value.toString(16).padStart(64, '0'), 'hex')
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1)
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes])
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes])
}
export function derEncode(r, s) {
  const body = Buffer.concat([derInteger(r), derInteger(s)])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}
// Strict DER decoding: one SEQUENCE of two minimal positive INTEGERs, nothing trailing.
export function derDecode(bytes) {
  const fault = () => new EcError('signature-encoding')
  const data = Buffer.from(bytes)
  if (data.length < 8 || data[0] !== 0x30 || data[1] !== data.length - 2) throw fault()
  let at = 2
  const integer = () => {
    if (data[at] !== 0x02) throw fault()
    const length = data[at + 1]
    const value = data.subarray(at + 2, at + 2 + length)
    if (length === 0 || value.length !== length || (value[0] & 0x80) || (length > 1 && value[0] === 0 && !(value[1] & 0x80))) throw fault()
    at += 2 + length
    return toInt(value)
  }
  const r = integer(), s = integer()
  if (at !== data.length) throw fault()
  return { r, s }
}
// The module's `k1sign` result: RFC 6979 over the 32 bytes as given, low-S, DER.
export function k1Sign(d, hash) {
  const { r, s } = signDeterministic(d, hash, SECP256K1)
  return derEncode(r, lowS(s, SECP256K1))
}
// ECDSA verification over a digest, in BigInt with OpenSSL scalar multiplication; accepts either S.
export function ecdsaVerify(curve, publicKey, digest, r, s) {
  if (r <= 0n || r >= curve.n || s <= 0n || s >= curve.n) return false
  const w = modInverse(s, curve.n)
  const u1 = mod(mod(toInt(digest), curve.n) * w, curve.n), u2 = mod(r * w, curve.n)
  const a = u1 === 0n ? null : mulBase(curve, u1)
  const b = u2 === 0n ? null : ecdhPoint(curve, u2, publicKey)
  const sum = addPoints(curve, a, b)
  return sum !== null && mod(sum.x, curve.n) === r
}

// ---- RFC 7518 §4.6: ECDH-ES+A256KW ---------------------------------------------

export function concatKdf(z, algorithm, apu, apv, bits) {
  if (bits !== 256) throw new RangeError('only A256KW (256-bit) keys are defined here')
  const field = bytes => Buffer.concat([u32(bytes.length), bytes])
  return sha256(Buffer.concat([u32(1), z, field(Buffer.from(algorithm, 'ascii')), field(apu), field(apv), u32(bits)]))
}
export function aesKeyUnwrap(kek, wrapped) {
  try {
    const decipher = createDecipheriv('id-aes256-wrap', kek, Buffer.from('a6a6a6a6a6a6a6a6', 'hex'))
    return Buffer.concat([decipher.update(wrapped), decipher.final()])
  } catch {
    throw new EcError('decrypt-failed', 'AES key unwrap')
  }
}
export function aesGcmDecrypt(key, iv, aad, ciphertext, tag) {
  if (iv.length !== 12 || tag.length !== 16) throw new EcError('decrypt-failed', 'A256GCM IV or tag length')
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAAD(aad)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    throw new EcError('decrypt-failed', 'A256GCM authentication')
  }
}

// ---- `decrypt`'s JWE entry (RFC 7516 §7.2.2; ENV §5.2, §9, §16) ----------------------

const JWE_MEMBERS = Object.freeze({ protected: true, header: true, encrypted_key: true, iv: true, ciphertext: true, tag: true, aad: false })
const HEADER_MEMBERS = Object.freeze(['alg', 'epk', 'kid', 'apu', 'apv'])
const B64U = /^[A-Za-z0-9_-]*$/
const isMap = value => value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value)
const fromB64u = text => Buffer.from(text, 'base64url')
// The shape SDX writes, checked before any key is used: the members of a flattened entry, base64url
// text, a protected header that is a JSON object, per-recipient members that never repeat a
// protected one, alg ECDH-ES+A256KW, and a P-256 epk JWK whose point passes point validation and
// whose y is the point's own. Returns the joint header and the ephemeral point.
export function checkJweShape(jwe) {
  const shape = what => new EcError('jwe-shape', what)
  if (!isMap(jwe)) throw shape('jwe is not a map')
  for (const name of Object.keys(jwe)) if (!Object.hasOwn(JWE_MEMBERS, name)) throw shape(`member ${name}`)
  for (const [name, required] of Object.entries(JWE_MEMBERS)) if (required && !(name in jwe)) throw shape(`missing ${name}`)
  for (const name of Object.keys(jwe)) if (name !== 'header' && (typeof jwe[name] !== 'string' || !B64U.test(jwe[name]))) throw shape(`${name} is not base64url text`)
  const header = jwe.header
  if (!isMap(header)) throw shape('header is not a map')
  for (const name of Object.keys(header)) if (!HEADER_MEMBERS.includes(name)) throw shape(`header member ${name}`)
  let prot
  try { prot = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromB64u(jwe.protected))) } catch { throw shape('protected is not base64url JSON') }
  if (!isMap(prot)) throw shape('protected is not a JSON object')
  for (const name of Object.keys(header)) if (Object.hasOwn(prot, name)) throw shape(`${name} in both headers`)
  const joint = { ...prot, ...header }
  if (joint.alg !== 'ECDH-ES+A256KW') throw shape('alg')
  if ('kid' in header && typeof header.kid !== 'string') throw shape('kid')
  for (const name of ['apu', 'apv']) if (name in joint && (typeof joint[name] !== 'string' || !B64U.test(joint[name]))) throw shape(name)
  const epk = joint.epk
  if (!isMap(epk) || Object.keys(epk).length !== 4 || !['kty', 'crv', 'x', 'y'].every(name => name in epk)) throw shape('epk members')
  if (epk.kty !== 'EC' || epk.crv !== 'P-256') throw shape('epk is not a P-256 key')
  if (typeof epk.x !== 'string' || typeof epk.y !== 'string' || !B64U.test(epk.x) || !B64U.test(epk.y)) throw shape('epk coordinates')
  const x = fromB64u(epk.x), y = fromB64u(epk.y)
  if (x.length !== 32 || y.length !== 32) throw shape('epk coordinate length')
  const ephemeral = Buffer.concat([Buffer.from([2 | (y[31] & 1)]), x])
  const point = decodePoint(P256, ephemeral)
  if (point.y !== toInt(y)) throw new EcError('point-not-on-curve', 'epk y')
  return { joint, ephemeral }
}
// The JWE decryption step with one candidate private key d: ECDH with epk, the Concat KDF, AES key
// unwrap and A256GCM over the protected header (and aad), as a JOSE implementation runs them.
export function jweDecrypt(d, jwe) {
  const { joint, ephemeral } = checkJweShape(jwe)
  if (joint.enc !== 'A256GCM' || 'zip' in joint || 'crit' in joint) throw new EcError('decrypt-failed', 'content algorithm')
  const z = ecdhX(P256, d, ephemeral)
  const kek = concatKdf(z, 'ECDH-ES+A256KW', fromB64u(joint.apu ?? ''), fromB64u(joint.apv ?? ''), 256)
  const cek = aesKeyUnwrap(kek, fromB64u(jwe.encrypted_key))
  const aad = Buffer.from(jwe.protected + ('aad' in jwe ? `.${jwe.aad}` : ''), 'ascii')
  return { z, kek, cek, plaintext: aesGcmDecrypt(cek, fromB64u(jwe.iv), aad, fromB64u(jwe.ciphertext), fromB64u(jwe.tag)) }
}

// ---- deterministic CBOR inputs: text keys to text, byte strings or integers ---

function head(major, value) {
  const m = major << 5
  const n = BigInt(value)
  if (n < 24n) return Buffer.from([m | Number(n)])
  if (n < 0x100n) return Buffer.from([m | 24, Number(n)])
  if (n < 0x10000n) return Buffer.concat([Buffer.from([m | 25]), u32(Number(n)).subarray(2)])
  if (n < 0x100000000n) return Buffer.concat([Buffer.from([m | 26]), u32(Number(n))])
  if (n < 1n << 64n) { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(n); return Buffer.concat([Buffer.from([m | 27]), bytes]) }
  throw new RangeError('CBOR length')
}
function encodeItem(value) {
  if (typeof value === 'string') { const bytes = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, bytes.length), bytes]) }
  if (typeof value === 'bigint' || typeof value === 'number') {
    const n = BigInt(value)
    return n >= 0n ? head(0, n) : head(1, -1n - n)
  }
  if (isMap(value)) return encodeInput(value)
  const bytes = Buffer.from(value)
  return Buffer.concat([head(2, bytes.length), bytes])
}
// A map of text keys, in RFC 8949 §4.2.1 order: bytewise order of the encoded keys.
export function encodeInput(input) {
  const entries = Object.entries(input).map(([name, value]) => [encodeItem(name), encodeItem(value)]).sort((a, b) => Buffer.compare(a[0], b[0]))
  return Buffer.concat([head(5, entries.length), ...entries.flat()])
}
// Strict decoder: definite shortest-form lengths and integers, keys in RFC 8949
// §4.2.1 order without duplicates, UTF-8 text, nothing trailing. Integers decode
// to BigInt; text to strings; byte strings to Buffers; a nested map (text keys,
// as in `jwe`) to an object.
export function decodeInput(bytes) {
  const data = Buffer.from(bytes)
  const text = new TextDecoder('utf-8', { fatal: true })
  const fault = () => new EcError('input-encoding')
  let at = 0
  const take = count => {
    if (at + count > data.length) throw fault()
    const slice = data.subarray(at, at + count)
    at += count
    return slice
  }
  const readHead = majors => {
    const first = take(1)[0], major = first >> 5, info = first & 31
    if (!majors.includes(major)) throw fault()
    if (info < 24) return { major, value: BigInt(info) }
    const width = { 24: 1, 25: 2, 26: 4, 27: 8 }[info]
    if (!width) throw fault()
    const value = toInt(take(width))
    if (value < (width === 1 ? 24n : 1n << BigInt(4 * width))) throw fault()
    return { major, value }
  }
  const utf8 = raw => { try { return text.decode(raw) } catch { throw fault() } }
  const readMap = (count, depth) => {
    const map = Object.create(null)
    let previous = null
    for (let i = 0n; i < count; i++) {
      const start = at
      const { value: keyLength } = readHead([3])
      if (keyLength > BigInt(data.length)) throw fault()
      const name = utf8(take(Number(keyLength)))
      const encodedKey = data.subarray(start, at)
      if (previous && Buffer.compare(previous, encodedKey) >= 0) throw fault()
      previous = encodedKey
      const { major, value } = readHead(depth < 3 ? [0, 1, 2, 3, 5] : [0, 1, 2, 3])
      if (major === 0) map[name] = value
      else if (major === 1) map[name] = -1n - value
      else if (major === 5) { if (value > BigInt(data.length)) throw fault(); map[name] = readMap(value, depth + 1) }
      else {
        if (value > BigInt(data.length)) throw fault()
        const raw = take(Number(value))
        map[name] = major === 3 ? utf8(raw) : Buffer.from(raw)
      }
    }
    return map
  }
  const { value: count } = readHead([5])
  const input = readMap(count, 0)
  if (at !== data.length) throw fault()
  return input
}
// JSON view used by the vectors: `path` and `acct` are text, `ep` a JSON number,
// `jwe` the map itself, other members hex bytes; {"tstr"}, {"bstr"}, {"uint"} and
// {"nint"} mark a member of another major type.
const MARKERS = ['tstr', 'bstr', 'uint', 'nint']
const isMarker = value => isMap(value) && Object.keys(value).length === 1 && MARKERS.includes(Object.keys(value)[0])
export function inputFromJson(view) {
  const input = {}
  for (const [name, value] of Object.entries(view)) {
    const natural = memberType(name)
    if (natural === 'map' && isMap(value) && !isMarker(value)) input[name] = structuredClone(value)
    else if (typeof value === 'string') input[name] = natural === 'tstr' ? value : fromHex(value)
    else if (typeof value === 'number' && natural === 'uint' && Number.isSafeInteger(value) && value >= 0) input[name] = BigInt(value)
    else if (typeof value?.tstr === 'string') input[name] = value.tstr
    else if (typeof value?.bstr === 'string') input[name] = fromHex(value.bstr)
    else if (Number.isSafeInteger(value?.uint) && value.uint >= 0) input[name] = BigInt(value.uint)
    else if (Number.isSafeInteger(value?.nint) && value.nint < 0) input[name] = BigInt(value.nint)
    else throw new TypeError(`input member ${name}`)
  }
  return input
}

// ---- reference module semantics ----------------------------------------------

const LOGICAL = /^(write|read|root|actor|session) ([0-9a-f]{32})$/
export const parseLogical = text => { const match = LOGICAL.exec(text); return match ? { role: match[1], tag: match[2] } : null }
const reservedName = name => typeof name === 'string' && (name === SCHEME.trim() || name.startsWith(SCHEME))
const TYPE_CHECKS = { tstr: value => typeof value === 'string', uint: value => typeof value === 'bigint' && value >= 0n, bstr: value => Buffer.isBuffer(value), map: isMap }
// A derivation identifier `2-<namespace>-<keyPath>` (KEYS §1.7, §1.8.1).
export function parseIdentifier(path) {
  const match = /^([0-2])-([a-z0-9 ]+)-(.+)$/s.exec(path)
  if (!match) throw new EcError('path-identifier')
  return { level: Number(match[1]), namespace: match[2], keyPath: match[3] }
}
export const sessionIdOf = path => /\/session\/([0-9a-f]{32})(?:\/|$)/.exec(path)?.[1]
// KEYS §1.3 and §1.6.1 with the profile's keywords and purposes: the key path is 1 to 1033 bytes;
// for roles other than actor it is `account/<id>`, then `runtime/<id>`, then `action/<id>` with an
// optional registered `<purpose>/<id>`, or `session/<id>`. The delegation variant is not served.
// Role actor derives only its persistent key, `actor/<index>` under the delegation namespace,
// outside the runtime tree (KEYS §2.14.1).
export function checkKeyPath(keyPath, role, namespaceRole, { keywords, purposes }) {
  const length = Buffer.byteLength(keyPath, 'utf8')
  if (length === 0 || length > MAX_KEY_PATH_BYTES) throw new EcError('key-path-length')
  const grammar = () => new EcError('key-path-grammar', keyPath)
  const seg = keyPath.split('/')
  if (role === 'actor') {
    if (namespaceRole !== 'delegation' || seg.length !== 2 || seg[0] !== keywords.actor || !/^(?:0|[1-9][0-9]*)$/.test(seg[1])) throw grammar()
    return
  }
  if (seg.some(part => part.length === 0) || seg[0] !== keywords.account) throw grammar()
  if (seg.length === 2) return
  if (seg[2] !== keywords.runtime || seg.length < 4) throw grammar()
  if (seg.length === 4) return
  if (seg[4] === keywords.action && seg.length === 6) return
  if (seg[4] === keywords.action && seg.length === 8) {
    if (!purposes.includes(seg[6])) throw new EcError('purpose-unregistered', seg[6])
    return
  }
  if (seg[4] === keywords.session && seg.length === 6) return
  throw grammar()
}

function readInput(operation, carried) {
  if (!(carried instanceof Uint8Array)) throw new EcError('input-encoding')
  const input = decodeInput(carried)
  const { required, optional } = MEMBERS[operation]
  for (const name of Object.keys(input)) if (!required.includes(name) && !optional.includes(name)) throw new EcError('unknown-member', name)
  for (const name of required) if (!(name in input)) throw new EcError('missing-member', name)
  if ((operation === 'key' || operation === 'k1key') && 'peer' in input && !('path' in input)) throw new EcError('missing-member', 'path')
  for (const [name, value] of Object.entries(input)) if (!TYPE_CHECKS[memberType(name)](value)) throw new EcError('member-type', name)
  const curve = CURVE_OF[operation]
  if ('peer' in input) decodePoint(curve, input.peer)
  if ('hash' in input && input.hash.length !== 32) throw new EcError('hash-length')
  if ('jwe' in input) checkJweShape(input.jwe)
  return input
}

// A wallet with the module installed, built from one entry of a vectors file's
// `wallets` table. `call(method, args, options)` takes BRC-100 method arguments
// with `plaintext` and `ciphertext` as bytes and returns { ciphertext } or
// { plaintext }, or throws an error with a laboratory code. Options:
// `approve` - the user approves the prompt the request raises;
// `injectHmac` - replaces the derivation's HMAC output (KEYS §1.12 item 7), for
// this checker's own tests; no vector case uses it.
export function createWallet({ entry, profile, derivation }) {
  const labels = profile.labels
  const namespaces = new Map(profile.namespaces.map(row => [row.namespace, row]))
  const walletRoot = entry.walletRoot ? fromHex(entry.walletRoot) : null
  const derive = keyID => rootFromIkm(walletDerivedIkm(walletRoot, derivation, keyID), labels)
  const accounts = new Map()
  for (const account of entry.accounts) {
    const epochs = new Map()
    for (const epoch of account.epochs) {
      const root = epoch.derived ? rootFromIkm(walletDerivedIkm(fromHex(epoch.walletRoot), derivation, `${account.acct} ${epoch.ep}`), labels) : rootFromIkm(fromHex(epoch.ikm), labels)
      epochs.set(BigInt(epoch.ep), root)
    }
    accounts.set(account.tag, { acct: account.acct, current: BigInt(account.current), epochs })
  }
  const actor = entry.actor ? rootFromIkm(fromHex(entry.actor.ikm), labels) : null
  const sessions = new Map(Object.entries(entry.sessions ?? {}).map(([id, session]) => [id, rootFromIkm(fromHex(session.ikm), labels)]))
  const grants = entry.grants ?? []

  // Roots and selection, in two parts (decision D-ERRORS). `selectRequest` reads only the
  // request and runs before the grant check. `select` reads what the wallet holds and runs only
  // once the request is authorized, so a caller with no grant and no approval learns nothing of the
  // accounts and epochs the wallet holds, and makes it derive or draw nothing.
  function selectRequest(operation, role, input) {
    if (operation === 'open' || ACCOUNT_ROLES.includes(role)) return {}
    if ('ep' in input) throw new EcError('epoch-not-allowed', role)
    if (role === 'actor') return {}
    const sessionId = 'path' in input ? sessionIdOf(input.path) : undefined
    if (!sessionId) throw new EcError('session-not-selected')
    return { sessionId }
  }
  // Whether `open` creates an account or an epoch. It is read before authorization only to
  // require the prompt: creating never runs under a standing grant.
  function openCreates(tag, input) {
    const held = accounts.get(tag)
    const account = held?.acct === input.acct ? held : undefined
    return !account?.epochs.has(input.ep ?? account?.current ?? 0n)
  }
  // The root a request uses, or the epoch `open` creates.
  function select(operation, role, tag, input, sessionId) {
    if (operation === 'open') {
      const account = accounts.get(tag)
      if (account && account.acct !== input.acct) throw new EcError('account-tag-collision')
      const ep = input.ep ?? account?.current ?? 0n
      const held = account?.epochs.get(ep)
      if (held) return held
      if (!walletRoot) throw new EcError('cannot-create')
      return derive(`${input.acct} ${ep}`)
    }
    if (ACCOUNT_ROLES.includes(role)) {
      const account = accounts.get(tag)
      if (!account) throw new EcError('unknown-account')
      const root = account.epochs.get(input.ep ?? account.current)
      if (!root) throw new EcError('unknown-epoch')
      return root
    }
    if (role === 'actor') {
      if (!actor) throw new EcError('no-actor-root')
      return actor
    }
    // A session the wallet does not hold yet gets a fresh root on first use.
    if (!sessions.has(sessionId)) sessions.set(sessionId, rootFromIkm(randomBytes(64), labels))
    return sessions.get(sessionId)
  }

  function call(method, args = {}, { approve = false, injectHmac } = {}) {
    if (NAMED_METHODS[method]?.(args).some(reservedName)) throw new EcError('reserved-namespace', method)
    const protocolName = args.protocolID?.[1]
    if (typeof protocolName !== 'string' || !protocolName.startsWith(SCHEME)) throw new EcError('not-sdx-request')
    if (!PROTOCOL_METHODS.has(method) || (method !== 'encrypt' && method !== 'decrypt')) throw new EcError('method-not-permitted', method)
    const rest = protocolName.slice(SCHEME.length), space = rest.indexOf(' ')
    const operation = space < 0 ? rest : rest.slice(0, space)
    const logical = space < 0 ? '' : rest.slice(space + 1)
    if (!Object.hasOwn(OPERATIONS, operation)) throw new EcError('unknown-operation', operation)
    if (OPERATIONS[operation] !== method) throw new EcError('wrong-carrier', `${method} ${operation}`)
    if (args.protocolID[0] !== 2) throw new EcError('security-level')
    if (args.privileged === true) throw new EcError('privileged-not-supported')
    const parsed = parseLogical(logical)
    if (!parsed) throw new EcError('logical-protocol-id')
    const { role, tag } = parsed
    if ((args.counterparty ?? 'self') !== 'self') throw new EcError('counterparty-not-self')
    const input = readInput(operation, method === 'encrypt' ? args.plaintext : args.ciphertext)
    // The operation's own rules: `open`'s role and tag, and the path rules.
    if (operation === 'open') {
      if (role !== 'root') throw new EcError('open-role')
      if (accountTag(input.acct) !== tag) throw new EcError('account-tag-mismatch')
    }
    const curve = CURVE_OF[operation]
    if ('path' in input) {
      const { level, namespace } = parseIdentifier(input.path)
      if (level !== 2) throw new EcError('path-identifier')
      const registered = namespaces.get(namespace)
      if (!registered) throw new EcError('namespace-unregistered', namespace)
      if (!registered.curves.includes(curve.name)) throw new EcError('namespace-curve', namespace)
      if (registered.role === 'rotation') throw new EcError('namespace-rotation')
      if (operation === 'decrypt' && registered.role !== 'encryption') throw new EcError('namespace-decrypt', namespace)
      if ((operation === 'sign' || operation === 'k1sign') && registered.role === 'encryption') throw new EcError('namespace-encryption')
      checkKeyPath(parseIdentifier(input.path).keyPath, role, registered.role, profile)
    }
    const { sessionId } = selectRequest(operation, role, input)
    // The grant and its prefixes, or the user's approval. Creating never runs under a grant.
    if (!approve) {
      const grant = grants.find(entry => entry.protocolID[0] === 2 && entry.protocolID[1] === protocolName)
      if (!grant) throw new EcError('no-grant')
      if (operation === 'open' && openCreates(tag, input)) throw new EcError('prompt-required')
      if ('path' in input && !grant.prefixes.some(prefix => Buffer.from(input.path, 'utf8').subarray(0, Buffer.byteLength(prefix)).equals(Buffer.from(prefix, 'utf8')))) throw new EcError('path-not-granted')
    }
    const root = select(operation, role, tag, input, sessionId)
    const inject = injectHmac === undefined ? undefined : Buffer.from(injectHmac)
    const scalar = curve === P256 ? root.r : root.k
    const self = curve === P256 ? root.R : root.K
    const peer = input.peer ?? self
    switch (operation) {
      case 'open': return { ciphertext: Buffer.concat([root.R, root.K]) }
      case 'key': case 'k1key': return { ciphertext: 'path' in input ? ownChild(scalar, peer, input.path, curve, inject).publicKey : self }
      case 'peer': case 'k1peer': return { ciphertext: counterpartyChild(scalar, input.peer, input.path, curve, inject).publicKey }
      case 'sign': return { ciphertext: es256Sign(ownChild(scalar, peer, input.path, curve, inject).childPrivate, input.msg) }
      case 'k1sign': return { ciphertext: k1Sign(ownChild(scalar, peer, input.path, curve, inject).childPrivate, input.hash) }
      case 'decrypt': return { plaintext: jweDecrypt(ownChild(scalar, input.peer, input.path, curve, inject).childPrivate, input.jwe).plaintext }
    }
  }
  // The root a well-formed request selects, without permission checks (for checkers).
  const rootFor = (role, acct, { ep, path } = {}) => {
    const input = { ...(ep === undefined ? {} : { ep: BigInt(ep) }), ...(path === undefined ? {} : { path }) }
    return select('key', role, accountTag(acct), input, selectRequest('key', role, input).sessionId)
  }
  return { call, rootFor, accounts, actor, sessions, walletRoot }
}

// ---- shared checker harness -------------------------------------------------------

export class Mismatch extends Error {}
export const expect = (condition, message) => { if (!condition) throw new Mismatch(message) }
export const equalHex = (actual, expected, what) => expect(hex(actual) === expected, `${what}: got ${hex(actual)}, expected ${expected}`)
export function expectRejection(action, code) {
  try { action() } catch (error) {
    expect(error instanceof EcError || error instanceof CheckError, `expected ${code}, got ${error.message}`)
    expect(error.code === code, `expected ${code}, got ${error.code}`)
    return error
  }
  throw new Mismatch(`expected rejection ${code}, call succeeded`)
}
export function argsFromJson(method, args) {
  const copy = structuredClone(args)
  if (method === 'encrypt' && typeof copy.plaintext === 'string') copy.plaintext = fromHex(copy.plaintext)
  if (method === 'decrypt' && typeof copy.ciphertext === 'string') copy.ciphertext = fromHex(copy.ciphertext)
  return copy
}
export function checkCbor(request) {
  if (!request.input) return
  const carried = request.method === 'decrypt' ? request.args.ciphertext : request.args.plaintext
  equalHex(encodeInput(inputFromJson(request.input)), carried, 'deterministic CBOR of the input')
}
export const operationOf = request => request.args.protocolID[1].split(' ')[2]
export const logicalOf = request => request.args.protocolID[1].split(' ').slice(3).join(' ')
export const roleOf = request => parseLogical(logicalOf(request)).role

export function header(doc, suite, requirements, oraclePath) {
  expect(doc.schema === 'tpnil-sdx-vectors@0.1.0', 'schema')
  expect(doc.suite === suite && doc.claim === 'LAB_SELF_TEST_ONLY' && doc.status === 'PROPOSED', 'suite, claim or status')
  expect(JSON.stringify(doc.requirements) === JSON.stringify(requirements), 'requirements')
  const ids = doc.cases.map(entry => entry.id)
  expect(new Set(ids).size === ids.length, 'case IDs are unique')
  for (const requirement of requirements) expect(doc.cases.some(entry => entry.requirement === requirement), `no case for ${requirement}`)
  for (const entry of doc.cases) expect(requirements.includes(entry.requirement), `${entry.id}: requirement ${entry.requirement}`)
  expect(Array.isArray(doc.decisions) && doc.decisions.length > 0 && doc.oracles.some(oracle => oracle.path === oraclePath), 'decisions and oracles')
  for (const [acct, tag] of Object.entries(doc.profile.accountTags)) expect(accountTag(acct) === tag, `account tag of ${acct} is the first 16 bytes of SHA-256(accountId)`)
  const tag = accountTag(doc.profile.identifiers.accountId)
  for (const [role, logical] of Object.entries(doc.profile.logicalProtocolIDs)) expect(logical === `${role} ${tag}` && parseLogical(logical)?.role === role, `logical protocol ID ${role}`)
  const { wallets } = doc
  expect(wallets.profile.labels.secp256k1 && wallets.profile.labels.p256 && wallets.profile.labels.secp256k1 !== wallets.profile.labels.p256 && wallets.profile.namespaces.length === 6, 'wallet profile')
  expect(new Set(wallets.profile.namespaces.map(row => row.namespace)).size === 6, 'six distinct namespaces (KEYS §1.7)')
  // One profile: the suite's profile block and the wallets' profile carry the same strings (KEYS §1.3.1).
  const { keywords, purposes } = wallets.profile
  expect(['account', 'runtime', 'action', 'session', 'actor'].every(name => typeof keywords?.[name] === 'string' && keywords[name] && !keywords[name].includes('/')) && keywords.action !== keywords.session, 'key-path keywords (KEYS §1.6.1)')
  expect(Array.isArray(purposes) && purposes.length > 0 && new Set(purposes).size === purposes.length && purposes.every(word => word && !word.includes('/')), 'a closed set of level-4 purposes (KEYS §1.6.1)')
  expect(JSON.stringify(doc.profile.keywords) === JSON.stringify(keywords) && JSON.stringify(doc.profile.purposes) === JSON.stringify(purposes) && JSON.stringify(doc.profile.labels) === JSON.stringify(wallets.profile.labels), 'the profile block and the wallets\' profile agree')
  expect(wallets.profile.namespaces.every(row => Object.values(doc.profile.namespaces).includes(row.namespace)), 'the profile block names the same namespaces')
  expect(typeof doc.profile.formatIdentifier === 'string' && doc.profile.formatIdentifier.length > 0 && doc.profile.formatIdentifier !== 'sdx:record:v1', 'a format identifier of the laboratory\'s own (ENV §2.1)')
  const derivation = wallets.walletRootDerivation
  expect(derivation.protocolID[0] === 2 && derivation.protocolID[1] === 'admin sdx root' && derivation.counterparty === 'self' && derivation.salt === 'p sdx v1' && derivation.info === 'sdx root' && derivation.length === 64, 'wallet-root derivation')
  for (const [name, entry] of Object.entries(wallets.entries)) {
    for (const account of entry.accounts) {
      expect(accountTag(account.acct) === account.tag, `${name}: tag of ${account.acct}`)
      expect(account.epochs.some(epoch => epoch.ep === account.current) && account.epochs.every(epoch => epoch.ep <= account.current), `${name}: the current epoch of ${account.acct} is the highest`)
      for (const epoch of account.epochs) expect(epoch.derived === true ? epoch.walletRoot === entry.walletRoot && !('ikm' in epoch) : typeof epoch.ikm === 'string' && !('walletRoot' in epoch), `${name}: epoch ${epoch.ep} of ${account.acct} is either ikm or derived`)
    }
    for (const grant of entry.grants) {
      const name2 = grant.protocolID[1]
      expect(grant.protocolID[0] === 2 && name2.startsWith(SCHEME) && Object.hasOwn(OPERATIONS, name2.split(' ')[2]) && parseLogical(name2.split(' ').slice(3).join(' ')), `${name}: grant protocol ${name2}`)
      expect(Array.isArray(grant.prefixes) && grant.prefixes.every(prefix => prefix.endsWith('/')) && (grant.prefixes.length > 0 || name2.split(' ')[2] === 'open'), `${name}: grant prefixes end at a segment boundary`)
    }
  }
}
// Builds each wallet of the `wallets` table and checks the listed root public keys.
export function loadWallets(doc) {
  const { profile, walletRootDerivation: derivation, entries } = doc.wallets
  const wallets = {}
  for (const [name, entry] of Object.entries(entries)) {
    const wallet = createWallet({ entry, profile, derivation })
    for (const account of entry.accounts) {
      for (const epoch of account.epochs) {
        const root = wallet.accounts.get(account.tag).epochs.get(BigInt(epoch.ep))
        equalHex(root.R, epoch.R, `${name} ${account.acct} epoch ${epoch.ep} R`)
        equalHex(root.K, epoch.K, `${name} ${account.acct} epoch ${epoch.ep} K`)
      }
    }
    if (entry.actor) { equalHex(wallet.actor.R, entry.actor.R, `${name} actor R`); equalHex(wallet.actor.K, entry.actor.K, `${name} actor K`) }
    for (const [id, session] of Object.entries(entry.sessions ?? {})) {
      equalHex(wallet.sessions.get(id).R, session.R, `${name} session R`)
      equalHex(wallet.sessions.get(id).K, session.K, `${name} session K`)
    }
    wallets[name] = wallet
  }
  return wallets
}
// The fixed test roots: split cases and link openers use them.
export function loadTestRoots(doc) {
  const labels = doc.testKeys.labels
  const roots = {}
  for (const [name, listed] of Object.entries(doc.testKeys.roots)) {
    const ikm = fromHex(listed.ikm)
    if (listed.usable === false) {
      expectRejection(() => splitIkm(ikm, labels), 'ikm-unusable')
      continue
    }
    const root = rootFromIkm(ikm, labels)
    equalHex(root.secp256k1Seed, listed.secp256k1Seed, `${name} secp256k1 seed`)
    equalHex(root.p256Seed, listed.p256Seed, `${name} P-256 seed`)
    equalHex(root.K, listed.secp256k1PublicKey, `${name} secp256k1 public key`)
    equalHex(root.R, listed.p256PublicKey, `${name} P-256 public key`)
    roots[name] = root
  }
  return roots
}
export function run(doc, checks) {
  const report = { suite: doc.suite, cases: doc.cases.length, passed: 0, behavioural: 0, failures: [] }
  try { checks.header() } catch (error) { report.failures.push({ id: '(document)', message: error.message }); return report }
  for (const entry of doc.cases) {
    try {
      const check = checks[entry.kind]
      expect(check, `unknown kind ${entry.kind}`)
      if (check(entry) === 'behavioural') report.behavioural++
      else report.passed++
    } catch (error) {
      report.failures.push({ id: entry.id, message: error.message })
    }
  }
  return report
}
export const callCase = (wallet, request, options) => wallet.call(request.method, argsFromJson(request.method, request.args), options)
// The root a module case selects: the wallet, role, tag, `ep` and `path` of its request.
export function selectedRoot(wallets, doc, entry, request = entry.request) {
  const input = inputFromJson(request.input)
  const { role, tag } = parseLogical(logicalOf(request))
  const acct = Object.entries(doc.profile.accountTags).find(([, value]) => value === tag)?.[0]
  expect(acct !== undefined || !ACCOUNT_ROLES.includes(role), `tag ${tag} names a profile account`)
  return wallets[entry.wallet].rootFor(role, acct ?? doc.profile.identifiers.accountId, { ep: input.ep, path: input.path })
}
// The search results (components/sdx/p256/grind) must name the inputs the
// rejection cases use; the cases themselves prove the rejections.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
function checkSearches(grind, unusable, account, rejectedCase) {
  expect(grind.seed.ikm === grind.seed.prefix + BigInt(grind.seed.counter).toString(16).padStart(16, '0') && grind.seed.ikm === unusable.ikm, 'seed search result')
  const digits = Array.from({ length: 16 }, (_, i) => CROCKFORD[Number((BigInt(grind.path.counter) >> BigInt(5 * (15 - i))) & 31n)]).join('')
  expect(grind.path.identifier === grind.path.prefix + digits && rejectedCase.request.input.path === grind.path.identifier, 'path search result')
  equalHex(offsetMaterial(account.r, account.R, grind.path.identifier).sharedPoint, grind.path.hmacKey, 'path search HMAC key')
}
// Intermediate values of one P-256 module request, recomputed from the selected root.
function moduleIntermediates(root, entry, input) {
  const known = entry.intermediate
  if (!known) return
  const counterparty = input.peer ?? root.R
  const material = offsetMaterial(root.r, counterparty, input.path)
  if (known.sharedPoint) equalHex(material.sharedPoint, known.sharedPoint, 'shared point')
  if (known.hmac) equalHex(material.hmac, known.hmac, 'HMAC')
  if (known.childPrivate) equalHex(int32(ownChild(root.r, counterparty, input.path).childPrivate), known.childPrivate, 'child private key')
  if (known.digest) {
    equalHex(sha256(input.msg), known.digest, 'message digest')
    const { r, s } = signDeterministic(ownChild(root.r, counterparty, input.path).childPrivate, sha256(input.msg))
    equalHex(Buffer.concat([int32(r), int32(s)]), known.rfc6979, 'RFC 6979 signature before low-S')
    expect((s > P256.n / 2n) === known.normalised, 'normalised flag')
  }
  if (known.z) {
    // decrypt: the key agreement of the entry with the one candidate key, and what it unwraps.
    const child = ownChild(root.r, input.peer, input.path)
    const { joint, ephemeral } = checkJweShape(input.jwe)
    const z = ecdhX(P256, child.childPrivate, ephemeral)
    equalHex(z, known.z, 'ECDH Z')
    const kek = concatKdf(z, 'ECDH-ES+A256KW', fromB64u(joint.apu ?? ''), fromB64u(joint.apv ?? ''), 256)
    equalHex(kek, known.kek, 'Concat KDF key-encryption key')
    if (known.cek) equalHex(aesKeyUnwrap(kek, fromB64u(input.jwe.encrypted_key)), known.cek, 'content-encryption key')
    else expectRejection(() => aesKeyUnwrap(kek, fromB64u(input.jwe.encrypted_key)), 'decrypt-failed')
  }
}
// Offset values injected into the KEYS §1.12 item 7 check, on either curve.
export function checkOffsetRange(entry) {
  const check = entry.curve === 'p256' ? checkOffset : offsetScalar
  const code = entry.curve === 'p256' ? 'scalar-rejected' : 'ERR_DERIVATION_SCALAR'
  const n = entry.curve === 'p256' ? P256.n : SECP256K1.n
  const values = entry.values.map(value => toInt(fromHex(value.hmac)))
  expect([0n, 1n, n - 1n, n, n + 1n].every(value => values.includes(value)), 'the values KEYS §1.12 item 7 names')
  for (const { hmac, expected } of entry.values) {
    const value = toInt(fromHex(hmac))
    expect((expected === 'accept') === (value > 0n && value < n), `outcome of ${hmac}`)
    if (expected === 'accept') expect(check(fromHex(hmac)) === value, `offset ${hmac}`)
    else expectRejection(() => check(fromHex(hmac)), code)
  }
}
// One invalid point encoding: rejected by decoding, and by every listed request.
export function checkPointRejection(entry, wallets, positions) {
  const curve = { 'P-256': P256, secp256k1: SECP256K1 }[entry.curve]
  expect(curve, `curve ${entry.curve}`)
  const encoding = fromHex(entry.encoding)
  expectRejection(() => decodePoint(curve, encoding), entry.expected.error)
  if (entry.reducesTo) {
    const x = toInt(encoding.subarray(1))
    expect(x >= curve.p && hex(int32(x % curve.p)) === entry.reducesTo.x, 'reduced x')
    let valid = true
    try { decodePoint(curve, Buffer.concat([encoding.subarray(0, 1), int32(x % curve.p)])) } catch { valid = false }
    expect(valid === entry.reducesTo.validX, 'validity of the reduced x')
  }
  expect(entry.requests.length === positions, `every ${entry.curve} point position`)
  for (const request of entry.requests) {
    checkCbor(request)
    expect(CURVE_OF[operationOf(request)] === curve, `${request.operation} derives on ${entry.curve}`)
    expect(hex(inputFromJson(request.input)[request.field]) === entry.encoding, `${request.operation}.${request.field} carries the encoding`)
    expectRejection(() => callCase(wallets[entry.wallet], request), entry.expected.error)
  }
}

// ---- suite checkers ------------------------------------------------------------

export function checkVcP256(doc) {
  let wallets, roots
  const byId = new Map(doc.cases.map(entry => [entry.id, entry]))
  const resultOf = entry => entry.expected.ciphertext ?? entry.expected.plaintext
  const checks = {
    header() {
      header(doc, 'VC-P256', ['P256-01', 'P256-02', 'P256-03', 'P256-04'], 'src/sdx/p256.mjs')
      roots = loadTestRoots(doc)
      wallets = loadWallets(doc)
      checkSearches(doc.generator.grind, doc.testKeys.roots.unusable, roots.account, byId.get('key-offset-rejected'))
    },
    split(entry) {
      const ikm = fromHex(entry.input.ikm)
      if (entry.expected.error) {
        const error = expectRejection(() => splitIkm(ikm, entry.input.labels), entry.expected.error)
        expect(error.message.endsWith(entry.expected.curve), 'rejected curve')
        const raw = label => Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(label, 'utf8'), 32))
        equalHex(raw(entry.input.labels.secp256k1), entry.intermediate.secp256k1Seed, 'secp256k1 seed')
        equalHex(raw(entry.input.labels.p256), entry.intermediate.p256Seed, 'P-256 seed')
        expect(seedInRange('secp256k1', raw(entry.input.labels.secp256k1)) && !seedInRange('p256', raw(entry.input.labels.p256)), 'only the P-256 seed is out of range')
        return
      }
      const { secp256k1Seed, p256Seed } = splitIkm(ikm, entry.input.labels)
      equalHex(secp256k1Seed, entry.expected.secp256k1Seed, 'secp256k1 seed')
      equalHex(p256Seed, entry.expected.p256Seed, 'P-256 seed')
      equalHex(publicKeyFromPrivate(secp256k1Seed), entry.expected.secp256k1PublicKey, 'secp256k1 public key')
      equalHex(encodePoint(P256, mulBase(P256, toInt(p256Seed))), entry.expected.p256PublicKey, 'P-256 public key')
      equalHex(roots[entry.root].R, entry.expected.p256PublicKey, 'test key table')
    },
    // A root derived inside a wallet (draft §Canonical derivation step 1): d is the BRC-42 child
    // private key under [2, "admin sdx root"], key ID "<accountId> <epoch>" or "actor",
    // counterparty self; ikm = HKDF-SHA-256(d, salt "p sdx v1", info "sdx root", 64); then the split.
    'wallet-root'(entry) {
      const { input, expected, intermediate } = entry
      expect(input.protocolID[0] === 2 && input.protocolID[1] === 'admin sdx root' && input.counterparty === 'self', 'canonical protocol and counterparty')
      expect(input.salt === 'p sdx v1' && input.info === 'sdx root', 'canonical HKDF salt and info')
      expect(/^[1-9A-HJ-NP-Za-km-z]+ (0|[1-9][0-9]*)$/.test(input.keyID) || input.keyID === 'actor', 'key ID is "<accountId> <epoch>" or "actor"')
      const walletRoot = fromHex(input.walletRootPrivateKey)
      equalHex(createHash('sha256').update(input.walletRootLabel, 'utf8').digest(), input.walletRootPrivateKey, 'wallet root from its label')
      const invoice = invoiceNumber(input.protocolID, input.keyID)
      expect(invoice === intermediate.invoiceNumber, 'invoice number')
      const shared = sharedSecretPoint(walletRoot, publicKeyFromPrivate(walletRoot))
      equalHex(shared, intermediate.sharedPoint, 'shared point r·(r·G)')
      equalHex(createHmac('sha256', shared).update(invoice, 'utf8').digest(), intermediate.hmac, 'HMAC')
      const d = deriveChildPrivateKey({ rootPrivateKey: walletRoot, protocolID: input.protocolID, keyID: input.keyID, counterparty: 'self' })
      equalHex(d, expected.d, 'd')
      const ikm = Buffer.from(hkdfSync('sha256', d, Buffer.from(input.salt, 'utf8'), Buffer.from(input.info, 'utf8'), 64))
      equalHex(ikm, expected.ikm, 'ikm')
      const root = rootFromIkm(ikm, input.labels)
      equalHex(root.secp256k1Seed, expected.secp256k1Seed, 'secp256k1 seed')
      equalHex(root.p256Seed, expected.p256Seed, 'P-256 seed')
      equalHex(publicKeyFromPrivate(root.secp256k1Seed), expected.secp256k1PublicKey, 'secp256k1 public key')
      equalHex(root.R, expected.p256PublicKey, 'P-256 public key')
      equalHex(walletDerivedIkm(walletRoot, doc.wallets.walletRootDerivation, input.keyID), expected.ikm, 'wallet-root derivation of the wallets table')
    },
    'seed-range'(entry) {
      for (const { seed, expected } of entry.values) expect(seedInRange(entry.curve, fromHex(seed)) === (expected === 'accept'), `seed ${seed}`)
    },
    'offset-range'(entry) { checkOffsetRange(entry) },
    module(entry) {
      const wallet = wallets[entry.wallet]
      checkCbor(entry.request)
      const input = inputFromJson(entry.request.input)
      const operation = operationOf(entry.request)
      const options = { approve: entry.prompt === 'approve' }
      const call = (overrides = {}) => wallet.call(entry.request.method, { ...argsFromJson(entry.request.method, entry.request.args), ...overrides }, options)
      // Creation needs the approved prompt; without it the same request is refused.
      if (entry.prompt === 'approve') expectRejection(() => callCase(wallet, entry.request), 'prompt-required')
      if (entry.expected.error) {
        expectRejection(() => call(), entry.expected.error)
        if ('path' in input) moduleIntermediates(selectedRoot(wallets, doc, entry), entry, input)
        if (entry.expected.error === 'scalar-rejected') expect(toInt(fromHex(entry.intermediate.hmac)) >= P256.n, 'grind HMAC is >= n')
        return
      }
      if (operation !== 'open' && 'path' in input) moduleIntermediates(selectedRoot(wallets, doc, entry), entry, input)
      const result = call()
      equalHex(result.ciphertext ?? result.plaintext, resultOf(entry), `${operation} result`)
      if (operation === 'key' && !('path' in input)) equalHex(selectedRoot(wallets, doc, entry).R, resultOf(entry), 'root public key')
      if (operation === 'open') {
        expect(resultOf(entry).length === 132, 'open returns 66 bytes')
        if (entry.matches) {
          const derived = byId.get(entry.matches).expected
          expect(resultOf(entry) === derived.p256PublicKey + derived.secp256k1PublicKey, `R || K of ${entry.matches}`)
        }
      }
      for (const variant of entry.variants ?? []) equalHex(call(variant).ciphertext, resultOf(entry), `variant ${JSON.stringify(variant)}`)
      if (entry.sameAs) expect(resultOf(byId.get(entry.sameAs)) === resultOf(entry), `same as ${entry.sameAs}`)
      if (entry.differsFrom) expect(resultOf(byId.get(entry.differsFrom)) !== resultOf(entry), `differs from ${entry.differsFrom}`)
      if (operation === 'sign') {
        const root = selectedRoot(wallets, doc, entry)
        const signer = ownChild(root.r, input.peer ?? root.R, input.path).publicKey
        expect(toInt(result.ciphertext.subarray(32)) <= P256.n / 2n, 'low-S')
        expect(es256Verify(signer, input.msg, result.ciphertext), 'ES256 verification')
      }
      if (operation === 'decrypt') checkDecrypt(entry, input)
    },
    'es256-external'(entry) {
      const d = toInt(fromHex(entry.privateKey)), message = fromHex(entry.message)
      equalHex(encodePoint(P256, mulBase(P256, d)), entry.publicKey, 'public key')
      const { r, s, k } = signDeterministic(d, sha256(message))
      equalHex(int32(k), entry.expected.k, 'RFC 6979 nonce')
      equalHex(Buffer.concat([int32(r), int32(s)]), entry.expected.rfc6979, 'RFC 6979 (r, s)')
      equalHex(es256Sign(d, message), entry.expected.signature, 'low-S signature')
      expect((s > P256.n / 2n) === entry.expected.normalised, 'normalised flag')
      expect(es256Verify(fromHex(entry.publicKey), message, fromHex(entry.expected.signature)), 'verifies in low-S form')
      expect(es256Verify(fromHex(entry.publicKey), message, fromHex(entry.expected.rfc6979)), 'verifies in the RFC form')
    },
    'point-rejection'(entry) { checkPointRejection(entry, wallets, 4) },
    'request-rejection'(entry) {
      checkCbor(entry.request)
      expectRejection(() => callCase(wallets[entry.wallet], entry.request), entry.expected.error)
    },
    behaviour(entry) {
      expect(['given', 'when', 'then'].every(name => typeof entry[name] === 'string' && entry[name].length), 'behaviour text')
      return 'behavioural'
    }
  }
  // A decrypt result: the entry is addressed to the one candidate key, an outer wrap names the
  // profile's format identifier and the record in its protected header (ENV §5.2), and the
  // plaintext is what the entry decrypts to with node:crypto.
  function checkDecrypt(entry, input) {
    const root = selectedRoot(wallets, doc, entry)
    const child = ownChild(root.r, input.peer, input.path)
    equalHex(child.publicKey, input.jwe.header.kid, 'the entry\'s kid is the one candidate key')
    const { joint } = checkJweShape(input.jwe)
    expect(joint.enc === 'A256GCM', 'A256GCM content')
    const keyPath = parseIdentifier(input.path).keyPath
    const fieldMatch = keyPath.split('/').length === 8
    if (!fieldMatch) {
      expect(joint.proto === doc.profile.formatIdentifier, 'the outer wrap carries the profile\'s format identifier')
      expect(keyPath.endsWith(`/${doc.wallets.profile.keywords.action}/${joint.aid}`), 'the outer wrap\'s aid names the record of the key path')
    } else expect(!('proto' in joint) && !('aid' in joint) && keyPath.split('/')[6] === 'field', 'a per-field JWE')
    const { plaintext, cek } = jweDecrypt(child.childPrivate, input.jwe)
    equalHex(plaintext, entry.expected.plaintext, 'plaintext by node:crypto')
    equalHex(cek, entry.intermediate.cek, 'content-encryption key')
  }
  return run(doc, checks)
}
