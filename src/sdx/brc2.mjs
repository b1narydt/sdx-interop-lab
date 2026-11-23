import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { deriveChildPrivateKey, deriveChildPublicKey, ecdhX, fail, privateKeyBytes, publicKeyFromPrivate, toBytes, decodePoint } from './brc42.mjs'

// Independent BRC-2 and BRC-78 oracle on node:crypto. It imports no wallet, SDK or
// Toolbox code. BRC-2 ciphertext is IV(32) ‖ AES-256-GCM ciphertext ‖ tag(16), with no
// additional authenticated data; the key is the 32-byte X coordinate of the shared point
// between the caller's child private key and the counterparty's child public key.

export const IV_BYTES = 32
export const TAG_BYTES = 16
export const BRC78_VERSION = Buffer.from('42421033', 'hex')
export const BRC78_PROTOCOL = Object.freeze([2, 'message encryption'])
export const BRC78_HEADER_BYTES = 4 + 33 + 33 + 32

export function brc2Key({ rootPrivateKey, protocolID, keyID, counterparty }) {
  if (counterparty === 'anyone') fail('ERR_COUNTERPARTY', 'BRC-2 encryption to anyone is not defined')
  const ownChild = deriveChildPrivateKey({ rootPrivateKey, protocolID, keyID, counterparty })
  const peerChild = deriveChildPublicKey({ rootPrivateKey, protocolID, keyID, counterparty, forSelf: false })
  return ecdhX(ownChild, peerChild)
}

export function brc2Encrypt({ plaintext, iv = randomBytes(IV_BYTES), ...derivation }) {
  const nonce = toBytes(iv, IV_BYTES, 'ERR_BRC2_LENGTH', 'BRC-2 IV')
  const key = brc2Key(derivation)
  try {
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES })
    return Buffer.concat([nonce, cipher.update(toBytes(plaintext, undefined, 'ERR_PLAINTEXT', 'plaintext')), cipher.final(), cipher.getAuthTag()])
  } finally { key.fill(0) }
}

export function brc2Decrypt({ ciphertext, ...derivation }) {
  const bytes = toBytes(ciphertext, undefined, 'ERR_BRC2_LENGTH', 'BRC-2 ciphertext')
  if (bytes.length < IV_BYTES + TAG_BYTES) fail('ERR_BRC2_LENGTH', `BRC-2 ciphertext must be at least ${IV_BYTES + TAG_BYTES} bytes`)
  const key = brc2Key(derivation)
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, IV_BYTES), { authTagLength: TAG_BYTES })
    decipher.setAuthTag(bytes.subarray(-TAG_BYTES))
    return Buffer.concat([decipher.update(bytes.subarray(IV_BYTES, -TAG_BYTES)), decipher.final()])
  } catch { fail('ERR_BRC2_DECRYPT', 'BRC-2 authentication failed') }
  finally { key.fill(0) }
}

/** BRC-78: version(4) ‖ sender(33) ‖ recipient(33) ‖ keyID(32) ‖ BRC-2 ciphertext. */
export function parseBrc78(message) {
  const bytes = toBytes(message, undefined, 'ERR_BRC78_FORMAT', 'BRC-78 message')
  if (bytes.length < BRC78_HEADER_BYTES + IV_BYTES + TAG_BYTES) fail('ERR_BRC78_FORMAT', 'BRC-78 message is too short')
  if (!bytes.subarray(0, 4).equals(BRC78_VERSION)) fail('ERR_BRC78_FORMAT', 'BRC-78 version is not 42421033')
  const sender = bytes.subarray(4, 37), recipient = bytes.subarray(37, 70)
  decodePoint(sender, 'ERR_BRC78_FORMAT'); decodePoint(recipient, 'ERR_BRC78_FORMAT')
  return { sender, recipient, keyID: bytes.subarray(70, 102), ciphertext: bytes.subarray(102) }
}

const brc78Derivation = (rootPrivateKey, counterparty, keyID) =>
  ({ rootPrivateKey, protocolID: BRC78_PROTOCOL, keyID: Buffer.from(keyID).toString('base64'), counterparty: Buffer.from(counterparty).toString('hex') })

export function brc78Decrypt(message, recipientPrivateKey) {
  const parsed = parseBrc78(message)
  if (!parsed.recipient.equals(publicKeyFromPrivate(recipientPrivateKey))) fail('ERR_BRC78_RECIPIENT', 'BRC-78 recipient is not this key')
  return brc2Decrypt({ ciphertext: parsed.ciphertext, ...brc78Derivation(recipientPrivateKey, parsed.sender, parsed.keyID) })
}

export function brc78Encrypt(plaintext, senderPrivateKey, recipientPublicKey, { keyID = randomBytes(32), iv } = {}) {
  const recipient = toBytes(recipientPublicKey, 33, 'ERR_POINT', 'recipient')
  decodePoint(recipient)
  const id = toBytes(keyID, 32, 'ERR_BRC78_FORMAT', 'BRC-78 key ID')
  const ciphertext = brc2Encrypt({ plaintext, iv, ...brc78Derivation(privateKeyBytes(senderPrivateKey), recipient, id) })
  return Buffer.concat([BRC78_VERSION, publicKeyFromPrivate(senderPrivateKey), recipient, id, ciphertext])
}
