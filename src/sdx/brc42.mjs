import { createECDH, createHmac } from 'node:crypto'

// Independent secp256k1 BRC-42 derivation oracle (SDX KEYS §1.8). It imports no wallet,
// SDK or Toolbox code.
//
// node:crypto supplies scalar multiplication by G (ECDH public keys), the X coordinate of
// every ECDH shared point, and HMAC-SHA-256. Two operations are not exposed by node:crypto:
// the Y parity of a shared point, which the SEC1-compressed HMAC key of KEYS §1.8.2 needs,
// and point addition, which a child public key R + h·G needs. This module implements both
// with minimal affine BigInt arithmetic and requires the BigInt shared point's X to equal
// node:crypto's computeSecret result, so two implementations agree on every shared point.
// The arithmetic is not constant-time. It is a laboratory oracle for public test keys only.

export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
export const G = Object.freeze({
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
})
export const ANYONE_PRIVATE_KEY = Buffer.from('00'.repeat(31) + '01', 'hex')
export const KEY_ID_MAX_BYTES = 800

export class CheckError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`)
    this.code = code
    Object.assign(this, details)
  }
}
export function fail(code, message, details) { throw new CheckError(code, message, details) }

const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r }
function power(base, exponent, m) {
  let result = 1n, b = mod(base, m), e = exponent
  while (e > 0n) { if (e & 1n) result = result * b % m; b = b * b % m; e >>= 1n }
  return result
}
const invert = (a, m = P) => power(a, m - 2n, m)

export const bigFromBytes = bytes => bytes.length === 0 ? 0n : BigInt('0x' + Buffer.from(bytes).toString('hex'))
export const bytesFromBig = (value, length = 32) => {
  const hex = value.toString(16)
  if (value < 0n || hex.length > length * 2) throw new RangeError('integer does not fit')
  return Buffer.from(hex.padStart(length * 2, '0'), 'hex')
}

/** Accept a Buffer, Uint8Array or lowercase/uppercase hex string of an exact length. */
export function toBytes(value, length, code, label) {
  let bytes
  if (typeof value === 'string') {
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) fail(code, `${label} is not hex`)
    bytes = Buffer.from(value, 'hex')
  } else if (value instanceof Uint8Array) bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength)
  else fail(code, `${label} must be bytes or hex`)
  if (length !== undefined && bytes.length !== length) fail(code, `${label} must be ${length} bytes, got ${bytes.length}`)
  return bytes
}

export function privateKeyBytes(value) {
  const bytes = toBytes(value, 32, 'ERR_PRIVATE_KEY', 'private key')
  const d = bigFromBytes(bytes)
  if (d === 0n || d >= N) fail('ERR_PRIVATE_KEY', 'private key is outside [1, n-1]')
  return bytes
}

/** Strict SEC1 compressed point decoding: 33 bytes, prefix 02/03, x < p, on the curve. */
export function decodePoint(value, code = 'ERR_POINT') {
  const bytes = toBytes(value, 33, code, 'public key')
  if (bytes[0] !== 2 && bytes[0] !== 3) fail(code, 'public key prefix must be 02 or 03')
  const x = bigFromBytes(bytes.subarray(1))
  if (x >= P) fail(code, 'public key x is not below p')
  const rhs = mod(x * x * x + 7n)
  let y = power(rhs, (P + 1n) / 4n, P)
  if (mod(y * y) !== rhs) fail(code, 'public key is not on secp256k1')
  if ((y & 1n) !== BigInt(bytes[0] & 1)) y = P - y
  return { x, y }
}
export function encodePoint(point) {
  if (point === null) fail('ERR_POINT', 'point at infinity has no encoding')
  return Buffer.concat([Buffer.from([point.y & 1n ? 3 : 2]), bytesFromBig(point.x)])
}
export function pointAdd(a, b) {
  if (a === null) return b
  if (b === null) return a
  let slope
  if (a.x === b.x) {
    if (mod(a.y + b.y) === 0n) return null
    slope = mod(3n * a.x * a.x * invert(2n * a.y))
  } else slope = mod((b.y - a.y) * invert(mod(b.x - a.x)))
  const x = mod(slope * slope - a.x - b.x)
  return { x, y: mod(slope * (a.x - x) - a.y) }
}
// Jacobian coordinates (x = X/Z², y = Y/Z³) for scalar multiplication on y² = x³ + 7, so
// a multiplication needs one field inversion instead of one per step.
function jacobianDouble([X, Y, Z]) {
  if (Y === 0n || Z === 0n) return [0n, 1n, 0n]
  const A = mod(X * X), B = mod(Y * Y), C = mod(B * B)
  const D = mod(2n * (mod((X + B) * (X + B)) - A - C)), E = mod(3n * A), F = mod(E * E)
  const X3 = mod(F - 2n * D)
  return [X3, mod(E * (D - X3) - 8n * C), mod(2n * Y * Z)]
}
function jacobianAdd(p, q) {
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q
  if (Z1 === 0n) return q
  if (Z2 === 0n) return p
  const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2)
  const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1), S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1)
  if (U1 === U2) return S1 === S2 ? jacobianDouble(p) : [0n, 1n, 0n]
  const H = mod(U2 - U1), I = mod(4n * H * H), J = mod(H * I), r = mod(2n * (S2 - S1)), V = mod(U1 * I)
  const X3 = mod(r * r - J - 2n * V)
  return [X3, mod(r * (V - X3) - 2n * S1 * J), mod((mod((Z1 + Z2) * (Z1 + Z2)) - Z1Z1 - Z2Z2) * H)]
}
export function pointMultiply(scalar, point) {
  if (point === null) return null
  let result = [0n, 1n, 0n], addend = [point.x, point.y, 1n], k = mod(scalar, N)
  while (k > 0n) { if (k & 1n) result = jacobianAdd(result, addend); addend = jacobianDouble(addend); k >>= 1n }
  const [X, Y, Z] = result
  if (Z === 0n) return null
  const zInverse = invert(Z), zInverse2 = mod(zInverse * zInverse)
  return { x: mod(X * zInverse2), y: mod(Y * zInverse2 * zInverse) }
}

/** k·G through node:crypto (OpenSSL), compressed. */
export function publicKeyFromPrivate(privateKey) {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(privateKeyBytes(privateKey))
  return ecdh.getPublicKey(null, 'compressed')
}

/** X coordinate of d·Q through node:crypto (OpenSSL). Rejects invalid points. */
export function ecdhX(privateKey, publicKey) {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(privateKeyBytes(privateKey))
  try { return ecdh.computeSecret(toBytes(publicKey, 33, 'ERR_POINT', 'public key')) }
  catch { fail('ERR_POINT', 'node:crypto rejected the public key') }
}

/** SEC1-compressed d·Q. BigInt supplies the parity; node:crypto must agree on X. */
export function sharedSecretPoint(privateKey, publicKey) {
  const d = bigFromBytes(privateKeyBytes(privateKey))
  const shared = encodePoint(pointMultiply(d, decodePoint(publicKey)))
  if (!shared.subarray(1).equals(ecdhX(privateKey, publicKey))) fail('ERR_INTERNAL', 'BigInt and node:crypto shared points differ')
  return shared
}

/** BRC-43 canonical protocol name. SDX forbids rewriting derivation strings, so a
 * non-canonical name is refused here rather than normalised as BRC-43 clients do. */
export function invoiceNumber(protocolID, keyID) {
  if (!Array.isArray(protocolID) || protocolID.length !== 2) fail('ERR_PROTOCOL_ID', 'protocolID must be [securityLevel, protocolName]')
  const [level, name] = protocolID
  if (![0, 1, 2].includes(level)) fail('ERR_PROTOCOL_ID', 'security level must be 0, 1 or 2')
  if (typeof name !== 'string') fail('ERR_PROTOCOL_ID', 'protocol name must be a string')
  const limit = name.startsWith('specific linkage revelation ') ? 430 : 400
  if (name.length < 5 || name.length > limit || !/^[a-z0-9 ]+$/.test(name) || name.includes('  ') ||
      name !== name.trim() || name.endsWith(' protocol')) fail('ERR_PROTOCOL_ID', `protocol name ${JSON.stringify(name)} is not BRC-43 canonical`)
  if (typeof keyID !== 'string') fail('ERR_KEY_ID', 'key ID must be a string')
  const keyBytes = Buffer.byteLength(keyID, 'utf8')
  if (keyBytes < 1 || keyBytes > KEY_ID_MAX_BYTES) fail('ERR_KEY_ID', `key ID must be 1 to ${KEY_ID_MAX_BYTES} UTF-8 bytes`)
  return `${level}-${name}-${keyID}`
}

const defaultHmac = (key, message) => createHmac('sha256', key).update(message).digest()

/** KEYS §1.8.2 scalar rejection: an HMAC that is 0 or ≥ n fails rather than being reduced. */
export function offsetScalar(hmacBytes) {
  const bytes = toBytes(hmacBytes, 32, 'ERR_DERIVATION_SCALAR', 'HMAC output')
  const h = bigFromBytes(bytes)
  if (h === 0n || h >= N) fail('ERR_DERIVATION_SCALAR', 'HMAC scalar is 0 or not below n')
  return h
}

export function counterpartyPublicKey(rootPrivateKey, counterparty) {
  if (counterparty === 'self') return publicKeyFromPrivate(rootPrivateKey)
  if (counterparty === 'anyone') return publicKeyFromPrivate(ANYONE_PRIVATE_KEY)
  const bytes = toBytes(counterparty, 33, 'ERR_COUNTERPARTY', 'counterparty')
  decodePoint(bytes, 'ERR_COUNTERPARTY')
  return bytes
}

/** BRC-69 method 2 offset: HMAC-SHA-256(compressed(root·counterparty), invoice). Returned as
 * the raw 32 HMAC bytes, after the KEYS §1.8.2 range check. */
export function specificLinkage({ rootPrivateKey, protocolID, keyID, counterparty, hmac = defaultHmac }) {
  const invoice = invoiceNumber(protocolID, keyID)
  const shared = sharedSecretPoint(rootPrivateKey, counterpartyPublicKey(rootPrivateKey, counterparty))
  const bytes = Buffer.from(hmac(shared, Buffer.from(invoice, 'utf8')))
  offsetScalar(bytes)
  return bytes
}

export function deriveChildPrivateKey({ rootPrivateKey, protocolID, keyID, counterparty, hmac }) {
  const h = offsetScalar(specificLinkage({ rootPrivateKey, protocolID, keyID, counterparty, hmac }))
  const child = mod(bigFromBytes(privateKeyBytes(rootPrivateKey)) + h, N)
  if (child === 0n) fail('ERR_DERIVATION_SCALAR', 'child private key is zero')
  return bytesFromBig(child)
}

/** R + h·G with h·G from node:crypto and the addition in BigInt. */
export function publicChildFromOffset(publicKey, offset) {
  const h = offsetScalar(offset)
  const sum = pointAdd(decodePoint(publicKey), decodePoint(publicKeyFromPrivate(bytesFromBig(h))))
  if (sum === null) fail('ERR_DERIVATION_POINT', 'child public key is the point at infinity')
  return encodePoint(sum)
}

/** BRC-100 getPublicKey semantics. forSelf: the caller's own child; otherwise the
 * counterparty's child as the caller derives it. Returns 33 compressed bytes. */
export function deriveChildPublicKey({ rootPrivateKey, protocolID, keyID, counterparty, forSelf = false, hmac }) {
  if (forSelf) return publicKeyFromPrivate(deriveChildPrivateKey({ rootPrivateKey, protocolID, keyID, counterparty, hmac }))
  const offset = specificLinkage({ rootPrivateKey, protocolID, keyID, counterparty, hmac })
  return publicChildFromOffset(counterpartyPublicKey(rootPrivateKey, counterparty), offset)
}
