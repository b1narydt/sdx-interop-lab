import { createECDH } from 'node:crypto'

// Minimal curve layer for the independent SDX checkers, on P-256 and secp256k1.
// Scalar multiplication is OpenSSL's, through node:crypto ECDH. node:crypto does
// not expose encoded point validation ahead of its parser, y recovery or point
// addition, so this file adds those in BigInt arithmetic. The laboratory's
// separate secp256k1 BRC-42 oracle, src/sdx/brc42.mjs, cross-checks the
// secp256k1 results. It does not import a wallet, Toolbox or generator library.
// It is not constant-time.
export const CURVES = Object.freeze({
  p256: Object.freeze({
    name: 'P-256', ecdh: 'prime256v1',
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
  }),
  secp256k1: Object.freeze({
    name: 'secp256k1', ecdh: 'secp256k1',
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    a: 0n,
    b: 7n,
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
  })
})

export class EcError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code)
    this.code = code
  }
}

export const mod = (a, m) => ((a % m) + m) % m
export function modPow(base, exponent, m) {
  let result = 1n, b = mod(base, m), e = exponent
  while (e > 0n) {
    if (e & 1n) result = result * b % m
    b = b * b % m
    e >>= 1n
  }
  return result
}
// Moduli here are prime, so Fermat's little theorem gives the inverse.
export const modInverse = (a, m) => {
  if (mod(a, m) === 0n) throw new EcError('no-inverse')
  return modPow(a, m - 2n, m)
}
export const toInt = bytes => bytes.length ? BigInt('0x' + Buffer.from(bytes).toString('hex')) : 0n
export const int32 = value => {
  if (value < 0n || value >= 1n << 256n) throw new RangeError('integer outside 32 bytes')
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex')
}

const rhs = (curve, x) => mod(x * x * x + curve.a * x + curve.b, curve.p)
export const isOnCurve = (curve, P) => P !== null && P.x >= 0n && P.x < curve.p && P.y >= 0n && P.y < curve.p && mod(P.y * P.y, curve.p) === rhs(curve, P.x)
export const basePoint = curve => ({ x: curve.gx, y: curve.gy })

// Square root mod p; both curves have p = 3 (mod 4).
function sqrt(curve, value) {
  const root = modPow(value, (curve.p + 1n) / 4n, curve.p)
  return mod(root * root, curve.p) === mod(value, curve.p) ? root : null
}

// Validation order of the sdx module draft (§Point validation) and BRC-229:
// exactly 33 bytes, prefix 02 or 03, x < p on the encoded integer before any
// reducing parser, on the curve, finite. A 33-byte compressed encoding cannot name the
// point at infinity, so the last rule holds for every input that passes the rest.
export function decodePoint(curve, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 33) throw new EcError('point-length', `${bytes?.length} bytes`)
  if (bytes[0] !== 2 && bytes[0] !== 3) throw new EcError('point-prefix', bytes[0].toString(16))
  const x = toInt(bytes.subarray(1))
  if (x >= curve.p) throw new EcError('point-x-range')
  let y = sqrt(curve, rhs(curve, x))
  if (y === null) throw new EcError('point-not-on-curve')
  if (Number(y & 1n) !== (bytes[0] & 1)) y = curve.p - y
  const point = { x, y }
  if (!isOnCurve(curve, point)) throw new EcError('point-not-on-curve')
  return point
}

export function encodePoint(curve, P) {
  if (P === null) throw new EcError('point-infinity')
  return Buffer.concat([Buffer.from([2 | Number(P.y & 1n)]), int32(P.x)])
}

export function addPoints(curve, P, Q) {
  if (P === null) return Q
  if (Q === null) return P
  let slope
  if (P.x === Q.x) {
    if (mod(P.y + Q.y, curve.p) === 0n) return null
    slope = mod((3n * P.x * P.x + curve.a) * modInverse(2n * P.y, curve.p), curve.p)
  } else {
    slope = mod((Q.y - P.y) * modInverse(Q.x - P.x, curve.p), curve.p)
  }
  const x = mod(slope * slope - P.x - Q.x, curve.p)
  return { x, y: mod(slope * (P.x - x) - P.y, curve.p) }
}

export const negate = (curve, P) => P === null ? null : { x: P.x, y: mod(-P.y, curve.p) }

function ecdh(curve, k) {
  if (k <= 0n || k >= curve.n) throw new EcError('scalar-range', curve.name)
  const context = createECDH(curve.ecdh)
  context.setPrivateKey(int32(k))
  return context
}

// k·G by OpenSSL, returned as a validated point.
export function mulBase(curve, k) {
  return decodePoint(curve, ecdh(curve, k).getPublicKey(null, 'compressed'))
}

// x(k·Q) by OpenSSL ECDH, after this file's own validation of Q.
export function ecdhX(curve, k, encodedQ) {
  decodePoint(curve, encodedQ)
  return ecdh(curve, k).computeSecret(Buffer.from(encodedQ))
}

// The full point k·Q. OpenSSL gives x(k·Q) and x((k+1)·Q); of the two points
// with that x, exactly one plus Q has the second x, since (S+Q) and (-S+Q)
// share an x only when 2Q = O, which a prime-order group excludes.
export function ecdhPoint(curve, k, encodedQ) {
  const Q = decodePoint(curve, encodedQ)
  if (k === curve.n - 1n) return negate(curve, Q)
  const x = toInt(ecdhX(curve, k, encodedQ))
  const y = sqrt(curve, rhs(curve, x))
  if (y === null) throw new EcError('ecdh-inconsistent')
  const next = toInt(ecdhX(curve, k + 1n, encodedQ))
  for (const candidate of [{ x, y }, { x, y: curve.p - y }]) {
    const sum = addPoints(curve, candidate, Q)
    if (sum !== null && sum.x === next) return candidate
  }
  throw new EcError('ecdh-inconsistent')
}
