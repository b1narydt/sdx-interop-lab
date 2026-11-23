// Public laboratory test keys and roots. Every private key and root here is published in the
// vector file and derived from a fixed label; none controls value on any real network.

import { createHash } from 'node:crypto'
import { Hash, KeyDeriver, PrivateKey } from '@bsv/sdk'

export const KEY_LABEL_PREFIX = 'TPNIL LAB_SELF_TEST_ONLY public test key: '
export const ROOT_LABEL_PREFIX = 'TPNIL LAB_SELF_TEST_ONLY VA-ANC public test root: '

const LABELS = {
  coinbase: 'Receives every synthetic coinbase output.',
  funding: 'P2PKH funding outputs for every action and the change of the master distribution.',
  handoffRecipient: 'The counterparty of the handoff entry in the transaction of action M3 (ANC §3.4); it holds no root in this suite.'
}

export function labKeys() {
  const keys = {}
  for (const [label, use] of Object.entries(LABELS)) {
    const privateKey = PrivateKey.fromHex(createHash('sha256').update(KEY_LABEL_PREFIX + label).digest('hex'))
    keys[label] = { label, use, privateKey, publicKey: privateKey.toPublicKey(), deriver: new KeyDeriver(privateKey) }
  }
  return keys
}

export function describeKeys(keys) {
  return Object.fromEntries(Object.values(keys).map(key => [key.label, {
    privateKey: key.privateKey.toHex().padStart(64, '0'),
    publicKey: key.publicKey.toString(),
    derivedFrom: `SHA-256("${KEY_LABEL_PREFIX}${key.label}")`,
    use: key.use
  }]))
}

// 64-byte roots (KEYS §1.4.1): SHA-512 of a published label. The participant holds one per
// epoch; the attacker root makes the forged origin entry.
export const ROOT_LABELS = Object.freeze({
  participant: { 0: 'participant, epoch 0', 1: 'participant, epoch 1', 2: 'participant, epoch 2' },
  attacker: { 0: 'attacker, epoch 0' }
})

export function labRoots() {
  const roots = {}
  for (const [holder, epochs] of Object.entries(ROOT_LABELS)) {
    roots[holder] = {}
    for (const [epoch, label] of Object.entries(epochs)) {
      roots[holder][epoch] = { root: createHash('sha512').update(ROOT_LABEL_PREFIX + label).digest(), label: ROOT_LABEL_PREFIX + label }
    }
  }
  return roots
}

// KEYS §1.4.2 split of a root into its secp256k1 seed, computed with @bsv/sdk's HMAC (an
// implementation separate from the checker's node:crypto HKDF).
export function secp256k1SeedOf(root, label) {
  const prk = Hash.sha256hmac(new Array(32).fill(0), [...root])
  return Buffer.from(Hash.sha256hmac(prk, [...Buffer.from(label, 'ascii'), 1]))
}
