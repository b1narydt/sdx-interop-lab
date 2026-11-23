import { sdk } from './oracle.mjs'

const { PrivateKey, Hash, BigNumber, Curve } = sdk

export const SCHEMA = 'tpnil-sdx-vectors@0.1.0'
export const CLAIM = 'LAB_SELF_TEST_ONLY'
export const STATUS = 'PROPOSED'

export const hex = bytes => Buffer.from(Uint8Array.from(bytes)).toString('hex')
export const fromHex = text => Array.from(Buffer.from(text, 'hex'))
export const utf8 = text => Array.from(Buffer.from(text, 'utf8'))
export const flip = (hexText, index, mask = 0x01) => { const bytes = Buffer.from(hexText, 'hex'); bytes[index] ^= mask; return bytes.toString('hex') }

// Public test keys. Accounts A and B are the secp256k1 halves of the KEYS §1.4.2 split of the
// 64-byte roots 00..3f and 40..7f, the roots the P-256 suites use. Party M's key is SHA-256 of a
// fixed label.
export const KEY_LABEL = 'TPNIL SDX v1 LAB_SELF_TEST_ONLY public test key: '
export const NOTE = 'public test key, not a secret, never funded'
const r1Ikm = first => hex(Array.from({ length: 64 }, (_, i) => first + i))
const K1_N = new Curve().n

function hkdfSha256(ikm, info, length = 32) {
  const prk = Hash.sha256hmac(new Array(32).fill(0), ikm)
  const okm = Hash.sha256hmac(prk, [...info, 1])
  if (length !== 32) throw new Error('one block only')
  return okm
}

function testKey(name, source) {
  let privateKey, origin
  if (typeof source === 'object') {
    const info = 'sdx-secp256k1', ikm = r1Ikm(source.ikmFirstByte)
    privateKey = hex(hkdfSha256(fromHex(ikm), utf8(info)))
    origin = { derivation: `KEYS §1.4.2 split: HKDF-SHA-256(ikm, salt "", info "${info}", L 32)`, ikm, info }
  } else {
    privateKey = hex(Hash.sha256(utf8(KEY_LABEL + source)))
    origin = { derivation: 'SHA-256(UTF-8(label))', label: KEY_LABEL + source }
  }
  const d = new BigNumber(privateKey, 16)
  if (d.isZero() || d.gte(K1_N)) throw new Error(`${name} is outside [1, n-1]`)
  const publicKey = PrivateKey.fromHex(privateKey).toPublicKey().toString()
  return { curve: 'secp256k1', privateKey, publicKey, ...origin, note: NOTE }
}

export const TEST_KEYS = Object.freeze({
  accountA: testKey('accountA', { ikmFirstByte: 0x00 }),
  accountB: testKey('accountB', { ikmFirstByte: 0x40 }),
  partyM: testKey('partyM', 'party M')
})
export const pick = (...names) => Object.fromEntries(names.map(name => [name, TEST_KEYS[name]]))
export const pub = name => TEST_KEYS[name].publicKey
export const priv = name => TEST_KEYS[name].privateKey
export const wallet = name => new sdk.ProtoWallet(PrivateKey.fromHex(priv(name)))

// Pinned standards. SDX text paths are the snapshots kept under fixtures/sdx/v1/standards.
export const DOCS = Object.freeze({
  program: 'programs/proposals/sdx-data-sharing/0.1.0/profile.json',
  b39rDraft: 'fixtures/sdx/v1/standards/draft-statements/brc-draft-brc39-recipient-protector.md'
})
const BRCS = {
  2: ['wallet/0002.md', '6e59dc9595038481c1d583f4e01d384dbdda9fd5'],
  39: ['outpoints/0039.md', '40b2f1d1c78686c5a4470898940d116738c3cf45'],
  42: ['key-derivation/0042.md', '5ac0c735f524ccdcd0c2b020a4be0b38981e68db'],
  43: ['key-derivation/0043.md', '5eb00be6fe5fca5a982d5c29b99ec5de136fdc5d'],
  69: ['key-derivation/0069.md', 'c92d5833b000811d2844b24791f51e08cb7c0753'],
  72: ['key-derivation/0072.md', '89641b6e2ed9b51cd68bf37a3ee92a7a0e9cc15c'],
  78: ['peer-to-peer/0078.md', '8060ce0b5155377e12dc6ecdfa2ef045544e84dd']
}
export const cite = (doc, clause) => ({ path: DOCS[doc], clause })
export const citeBrc = (brc, clause) => ({ brc, repository: 'bsv-blockchain/BRCs', path: BRCS[brc][0], gitBlob: BRCS[brc][1], clause })

export function generatorRecord(dependencies) {
  return {
    path: 'components/sdx/b39r/generate.mjs',
    runtime: `node ${process.versions.node}`,
    dependencies,
    lockfile: 'components/sdx/b39r/package-lock.json',
    frozenRandom: 'components/sdx/b39r/frozen-random.json'
  }
}

/** Values produced once by randomised operations (BRC-2 IVs, BRC-78 key IDs). A regenerate
 * reuses them, so every other byte must reproduce exactly. */
export class RandomStore {
  constructor(frozen = {}, { allowFresh = true } = {}) { this.frozen = frozen; this.allowFresh = allowFresh; this.used = {} }
  async take(slot, produce) {
    if (Object.hasOwn(this.used, slot)) return this.used[slot]
    let value
    if (Object.hasOwn(this.frozen, slot)) value = this.frozen[slot]
    else if (this.allowFresh) value = await produce()
    else throw new Error(`frozen random slot ${slot} is missing`)
    this.used[slot] = value
    return value
  }
}

export function assert(condition, message) { if (!condition) throw new Error(`generator self-check failed: ${message}`) }
export async function rejects(promiseOrFn, message) {
  try { await (typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn) } catch { return }
  throw new Error(`generator self-check failed: ${message} was accepted`)
}
