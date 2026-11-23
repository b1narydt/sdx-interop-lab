// Shared laboratory values for the VA-ENV, VA-SIG and VA-ADM generators: the published
// laboratory deployment profile, byte helpers, identifier formats and the public test
// identities. LAB_SELF_TEST_ONLY.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256, sha512 } from '@noble/hashes/sha2.js'

export const HERE = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
export const REPO = path.resolve(HERE, '../../..')
export const PROFILE_PATH = 'fixtures/sdx/v1/deployment-profile.json'
export const PROFILE_BYTES = fs.readFileSync(path.join(REPO, PROFILE_PATH))
export const PROFILE = JSON.parse(PROFILE_BYTES.toString('utf8'))

export const hex = bytes => Buffer.from(bytes).toString('hex')
export const unhex = text => Uint8Array.from(Buffer.from(text, 'hex'))
export const utf8 = text => new TextEncoder().encode(text)
export const b64u = bytes => Buffer.from(bytes).toString('base64url')
export const unb64u = text => Uint8Array.from(Buffer.from(text, 'base64url'))
export const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(part => Buffer.from(part))))
export const toBig = bytes => BigInt('0x' + (hex(bytes) || '0'))
export const be32 = value => unhex(value.toString(16).padStart(64, '0'))
export const fail = message => { throw new Error(`generator self-check failed: ${message}`) }

if (PROFILE.claim !== 'LAB_SELF_TEST_ONLY' || PROFILE.profile !== 'tpnil-sdx-lab:v1') fail('laboratory deployment profile')

// Every string that enters a derivation or the wire comes from the published profile
// (KEYS §1.3.1, ENV §2.1). The level-3 keyword is `action` on both curves (reading R1).
export const FORMAT = PROFILE.formatIdentifier.value
export const LABELS = PROFILE.derivation.curveLabels
export const NS = PROFILE.derivation.namespaces
export const KW = PROFILE.derivation.keyPath.keywords
export const PURPOSES = PROFILE.derivation.keyPath.purposes.map(entry => entry.purpose)

// Derivation identifiers (KEYS §1.8.1) of a record's keys: the signing key (ENV §8.5), the
// outer recipient key and the per-field recipient keys (ENV §8.6), and the secp256k1
// commitment key (ANC §3.1), all under one record-scoped key path.
export const recordPath = (acct, rid, aid) => `${KW.level1}/${acct}/${KW.level2}/${rid}/${KW.level3}/${aid}`
export const identifier = (namespace, keyPath) => `${PROFILE.derivation.securityLevel}-${namespace}-${keyPath}`
export const signId = (acct, rid, aid) => identifier(NS.signing, recordPath(acct, rid, aid))
export const outerId = (acct, rid, aid) => identifier(NS.encryption, recordPath(acct, rid, aid))
export const fieldId = (acct, rid, aid, name) => identifier(NS.encryption, `${recordPath(acct, rid, aid)}/field/${name}`)

// KEYS §1.6.2 names base58check for account and runtime identifiers without fixing a
// version byte or checksum. Laboratory construction: base58 (Bitcoin alphabet) of the 16
// identifier bytes followed by the first 4 bytes of SHA-256d of them, with no version byte.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function base58check(payload) {
  const check = sha256(sha256(payload)).subarray(0, 4)
  const bytes = concat(payload, check)
  let n = toBig(bytes)
  let out = ''
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n }
  for (const byte of bytes) { if (byte !== 0) break; out = '1' + out }
  return out
}

// ULID (KEYS §1.6.2): 48-bit millisecond time and 80 random bits, 26 Crockford base32 characters.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export function ulid(ms, random10) {
  if (random10.length !== 10) fail('ulid randomness')
  let n = (BigInt(ms) << 80n) | toBig(random10)
  let out = ''
  for (let i = 0; i < 26; i++) { out = CROCKFORD[Number(n & 31n)] + out; n >>= 5n }
  return out
}

// Public test identities. Each root is SHA-512 of a published label; none controls value.
const LABEL = 'TPNIL SDX v1 LAB_SELF_TEST_ONLY public test root'
export const rootIkm = name => sha512(utf8(`${LABEL}: ${name}`))
export const idOf = name => base58check(sha256(utf8(`${LABEL} identifier: ${name}`)).subarray(0, 16))
export const IDENTITIES = Object.fromEntries(['writer', 'readerA', 'readerB', 'outsider', 'writer2'].map(name => [name, {
  name,
  acct: idOf(`${name} account`),
  rid: idOf(`${name} runtime`),
  ep: 0,
  rootIkm: rootIkm(name)
}]))

// Writer-declared time of every laboratory record: 2026-11-15T00:00:00Z. Above 2^32, as
// every real timestamp is, so the superseded integer shape of ENV §8.3 differs from the current one.
export const TM = Date.UTC(2026, 10, 15)
