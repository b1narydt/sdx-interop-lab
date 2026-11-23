// Key material for the generators, on @noble/curves and @noble/hashes: the KEYS §1.4.2
// split, the KEYS §1.8.2 derivation on P-256 and secp256k1, and the ENV §4 content-derived
// secrets. The checkers do not import this file.
import { p256 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { pbkdf2 } from '@noble/hashes/pbkdf2.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { LABELS, be32, fail, hex, toBig, unhex, utf8 } from './lab.mjs'

export const N = p256.Point.CURVE().n
export const NK = secp256k1.Point.CURVE().n
const G = p256.Point.BASE

// KEYS §1.4.2: both seeds from the full 64 bytes, empty salt, the profile's labels, 32 bytes.
// KEYS §1.4.3: each seed must lie in [1, n-1].
export function split(ikm) {
  if (ikm.length !== 64) fail('root keying material must be 64 bytes')
  const k1Seed = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.secp256k1), 32)
  const p256Seed = hkdf(sha256, ikm, new Uint8Array(0), utf8(LABELS.p256), 32)
  for (const [seed, n] of [[k1Seed, NK], [p256Seed, N]]) if (toBig(seed) === 0n || toBig(seed) >= n) fail('seed out of range')
  return { ikm, k1Seed, p256Seed, R: p256.getPublicKey(p256Seed, true), K: secp256k1.getPublicKey(k1Seed, true) }
}

// KEYS §1.8.2 on P-256. S derives a child of R: shared = S.priv x R.pub, offset =
// HMAC-SHA-256(key = compressed shared point, message = identifier); an offset of 0 or at
// least n is refused (the laboratory reading of the clause). `own` returns the deriver's
// own child (counterparty R = the party it shares the secret with); `theirs` returns the
// counterparty's child public key.
function offset(curve, n, seed, counterparty, id) {
  const shared = curve.getSharedSecret(seed, counterparty, true)
  const mac = hmac(sha256, shared, utf8(id))
  const h = toBig(mac)
  if (h === 0n || h >= n) fail(`offset out of range for ${id}`)
  return { shared, mac, h }
}
export function p256Own(seed, counterparty, id) {
  const o = offset(p256, N, seed, counterparty, id)
  const d = be32((toBig(seed) + o.h) % N)
  return { ...o, d, pub: p256.getPublicKey(d, true) }
}
export function p256Theirs(seed, counterparty, id) {
  const o = offset(p256, N, seed, counterparty, id)
  return { ...o, pub: p256.Point.fromHex(hex(counterparty)).add(G.multiply(o.h)).toBytes(true) }
}
export const p256Self = (seed, id) => p256Own(seed, p256.getPublicKey(seed, true), id)
export function k1Self(seed, id) {
  const o = offset(secp256k1, NK, seed, secp256k1.getPublicKey(seed, true), id)
  const d = be32((toBig(seed) + o.h) % NK)
  return { ...o, d, pub: secp256k1.getPublicKey(d, true) }
}

// ES256 with an RFC 6979 nonce in low-S form, so the generator's output is reproducible.
// SDX does not require deterministic nonces (ENV §8.2, KEYS §1.8.3); signatures are compared
// by verification, never by bytes.
export const es256 = (d, message) => p256.sign(message, d, { lowS: true })
export const highS = signature => {
  const r = signature.subarray(0, 32), s = toBig(signature.subarray(32))
  return Uint8Array.from([...r, ...be32(N - s)])
}
export const p256Public = d => p256.getPublicKey(d, true)
export const p256Uncompressed = pub => p256.Point.fromHex(hex(pub)).toBytes(false)
export const p256Shared = (d, pub) => p256.getSharedSecret(d, pub, true)

// ENV §4: calculateSecrets. The HMAC key is s2 and the message is s1.
export const MIN_ITERATIONS = 200000
export function calculateSecrets(data, iterations = MIN_ITERATIONS) {
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS) fail('iterations below the ENV §4 floor')
  const hash = sha256(data)
  const cryptoKey = pbkdf2(sha256, data, hash, { c: iterations, dkLen: 64 })
  const s1 = cryptoKey.subarray(0, 32), s2 = cryptoKey.subarray(32, 64)
  return { hash, s1, s2, cek: hmac(sha256, s2, s1), reversed: hmac(sha256, s1, s2), iterations }
}

export const sha = bytes => sha256(bytes)
export const fromHex = unhex
