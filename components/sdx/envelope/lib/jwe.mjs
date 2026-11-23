// JWEs in the General JSON Serialization (RFC 7516 §7.2.1), built from frozen random values
// so that a writer given the same values reproduces the same key-management bytes. The
// generator builds each JWE on @noble primitives and then requires jose 6.2.17, a JOSE
// implementation (ENV §16), to open it for every recipient; jose also verifies every ES256
// signature. A stock jose GeneralEncrypt with one recipient writes `epk` into the protected
// header, where ENV §5.2 and §11 keep only {enc, proto, aid} (plus iter and salt), so the
// laboratory does not use jose to encrypt.
import { gcm, aeskw } from '@noble/ciphers/aes.js'
import { sha256 } from '@noble/hashes/sha2.js'
import * as jose from 'jose'
import { b64u, concat, fail, hex, unb64u, utf8 } from './lab.mjs'
import { p256Shared, p256Uncompressed } from './keys.mjs'
import { p256 } from '@noble/curves/nist.js'

export const ECDH = 'ECDH-ES+A256KW'
export const GCMKW = 'A256GCMKW'
const u32 = n => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
const lv = bytes => concat(u32(bytes.length), bytes)

// RFC 7518 §4.6.2: Concat KDF, one SHA-256 round for a 256-bit key; apu and apv absent.
export function concatKdf(z, alg) {
  const otherInfo = concat(lv(utf8(alg)), lv(new Uint8Array(0)), lv(new Uint8Array(0)), u32(256))
  return sha256(concat(u32(1), z, otherInfo))
}

export function epkJwk(epkPrivate) {
  const point = p256Uncompressed(p256.getPublicKey(epkPrivate, true))
  return { kty: 'EC', crv: 'P-256', x: b64u(point.subarray(1, 33)), y: b64u(point.subarray(33)) }
}

// recipients: { alg: ECDH, kid, pub, epk } | { alg: GCMKW, kek, kwiv }
// epkInProtected writes a single identity recipient's epk into the protected header, as a stock
// JOSE library does for one recipient; only the reader-leniency case uses it.
export function buildJwe({ protectedHeader, plaintext, cek, iv, recipients, epkInProtected = false }) {
  if (cek.length !== 32 || iv.length !== 12) fail('JWE CEK or IV length')
  if (epkInProtected && (recipients.length !== 1 || recipients[0].alg !== ECDH)) fail('epk in the protected header needs one identity recipient')
  const protectedB64 = b64u(utf8(JSON.stringify(epkInProtected ? { ...protectedHeader, epk: epkJwk(recipients[0].epk) } : protectedHeader)))
  const sealed = gcm(cek, iv, utf8(protectedB64)).encrypt(plaintext)
  const out = {
    protected: protectedB64,
    recipients: recipients.map(r => {
      if (r.alg === ECDH) {
        const z = p256Shared(r.epk, r.pub).subarray(1)
        const kek = concatKdf(z, ECDH)
        const header = epkInProtected ? { alg: ECDH, kid: r.kid } : { alg: ECDH, kid: r.kid, epk: epkJwk(r.epk) }
        return { header, encrypted_key: b64u(aeskw(kek).encrypt(cek)) }
      }
      if (r.alg === GCMKW) {
        const wrapped = gcm(r.kek, r.kwiv).encrypt(cek)
        return { header: { alg: GCMKW, iv: b64u(r.kwiv), tag: b64u(wrapped.subarray(32)) }, encrypted_key: b64u(wrapped.subarray(0, 32)) }
      }
      return fail(`recipient algorithm ${r.alg}`)
    }),
    iv: b64u(iv),
    ciphertext: b64u(sealed.subarray(0, sealed.length - 16)),
    tag: b64u(sealed.subarray(sealed.length - 16))
  }
  return out
}

// jose must open the JWE through each listed recipient and return the plaintext.
export async function joseOpens(jwe, index, key, plaintext) {
  const r = jwe.recipients[index]
  const flat = { protected: jwe.protected, header: r.header, encrypted_key: r.encrypted_key, iv: jwe.iv, ciphertext: jwe.ciphertext, tag: jwe.tag }
  const alg = r.header.alg
  const k = alg === ECDH
    ? await jose.importJWK({ kty: 'EC', crv: 'P-256', ...xy(p256.getPublicKey(key, true)), d: b64u(key) }, ECDH)
    : key
  const opened = await jose.flattenedDecrypt(flat, k, { keyManagementAlgorithms: [alg], contentEncryptionAlgorithms: ['A256GCM'] })
  if (hex(opened.plaintext) !== hex(plaintext)) fail('jose opened a JWE to other bytes')
}
const xy = pub => { const u = p256Uncompressed(pub); return { x: b64u(u.subarray(1, 33)), y: b64u(u.subarray(33)) } }

// ENV §8.2: a detached-payload ES256 JWS over the signing input protectedB64 "." payloadB64.
export const protectedSig = kid => b64u(utf8(JSON.stringify({ alg: 'ES256', kid })))
export async function joseVerifies(protectedB64, payloadB64, signature, pub) {
  const key = await jose.importJWK({ kty: 'EC', crv: 'P-256', ...xy(pub) }, 'ES256')
  try {
    await jose.flattenedVerify({ protected: protectedB64, payload: payloadB64, signature: b64u(signature) }, key, { algorithms: ['ES256'] })
    return true
  } catch (error) {
    if (error?.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') return false
    throw error
  }
}
export const signingInput = (protectedB64, signedBytes) => utf8(`${protectedB64}.${b64u(signedBytes)}`)
export { unb64u }
