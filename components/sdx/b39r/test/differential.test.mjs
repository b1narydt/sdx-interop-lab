// Randomised differential tests: the pinned oracles (@bsv/sdk 4.0.1 on its pure-TypeScript
// paths, @noble/ciphers 2.4.0) against the dependency-free node:crypto checkers in src/ that the
// BRC-39 recipient-protector suite uses. Inputs are fresh on every run; the frozen suite covers
// fixed inputs.
import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, randomInt } from 'node:crypto'
import { sdk, gcm } from '../oracle.mjs'
import * as k42 from '../../../../src/sdx/brc42.mjs'
import { brc2Decrypt, brc2Encrypt, brc78Decrypt, brc78Encrypt } from '../../../../src/sdx/brc2.mjs'
import { decryptRecipientFile, encryptRecipientFile } from '../../../../src/portability/brc39-recipient.mjs'

const { PrivateKey, ProtoWallet, KeyDeriver, EncryptedMessage } = sdk
const ROUNDS = 25
const hex = bytes => Buffer.from(Uint8Array.from(bytes)).toString('hex')
const scalar = () => { for (;;) { const bytes = randomBytes(32); const d = k42.bigFromBytes(bytes); if (d > 0n && d < k42.N) return bytes.toString('hex') } }
const protocols = [[2, 'sdx sign'], [2, 'sdx encrypt'], [1, 'sdx delegate'], [0, 'message encryption'], [2, 'specific linkage revelation 2 sdx sign']]
const keyIDs = () => ['account/3MNQpxFAsp/runtime/8kRt2wVbZq/record/01JB8ZK3QN7T4YVX2C9M5RDPWA', `k${randomInt(1e9)}`, 'é/field/ñame-' + randomBytes(4).toString('hex'), 'x'.repeat(800)][randomInt(4)]

test('LAB_SELF_TEST_ONLY: BRC-42 derivation agrees (getPublicKey both directions, derivePrivateKey, revealSpecificSecret)', async () => {
  for (let i = 0; i < ROUNDS; i++) {
    const root = scalar(), peerRoot = scalar(), protocolID = protocols[randomInt(protocols.length)], keyID = keyIDs()
    const peer = k42.publicKeyFromPrivate(peerRoot).toString('hex')
    const wallet = new ProtoWallet(PrivateKey.fromHex(root)), deriver = new KeyDeriver(PrivateKey.fromHex(root))
    for (const counterparty of ['self', 'anyone', peer]) {
      const derivation = { rootPrivateKey: root, protocolID, keyID, counterparty }
      for (const forSelf of [true, false]) {
        assert.equal((await wallet.getPublicKey({ protocolID, keyID, counterparty, forSelf })).publicKey, k42.deriveChildPublicKey({ ...derivation, forSelf }).toString('hex'))
      }
      assert.equal(deriver.derivePrivateKey(protocolID, keyID, counterparty).toHex().padStart(64, '0'), k42.deriveChildPrivateKey(derivation).toString('hex'))
      assert.equal(hex(deriver.revealSpecificSecret(counterparty, protocolID, keyID)), k42.specificLinkage(derivation).toString('hex'))
    }
  }
})

test('LAB_SELF_TEST_ONLY: BRC-2 and BRC-78 interoperate in both directions', async () => {
  for (let i = 0; i < ROUNDS; i++) {
    const a = scalar(), b = scalar(), protocolID = [2, 'sdx encrypt'], keyID = keyIDs(), plaintext = randomBytes(randomInt(0, 80))
    const A = k42.publicKeyFromPrivate(a).toString('hex'), B = k42.publicKeyFromPrivate(b).toString('hex')
    const fromSdk = (await new ProtoWallet(PrivateKey.fromHex(a)).encrypt({ protocolID, keyID, counterparty: B, plaintext: Array.from(plaintext) })).ciphertext
    assert.deepEqual(brc2Decrypt({ rootPrivateKey: b, protocolID, keyID, counterparty: A, ciphertext: Uint8Array.from(fromSdk) }), plaintext)
    const fromChecker = brc2Encrypt({ rootPrivateKey: b, protocolID, keyID, counterparty: A, plaintext })
    assert.equal(hex((await new ProtoWallet(PrivateKey.fromHex(a)).decrypt({ protocolID, keyID, counterparty: B, ciphertext: Array.from(fromChecker) })).plaintext), plaintext.toString('hex'))
    const selfSdk = (await new ProtoWallet(PrivateKey.fromHex(a)).encrypt({ protocolID, keyID, counterparty: 'self', plaintext: Array.from(plaintext) })).ciphertext
    assert.deepEqual(brc2Decrypt({ rootPrivateKey: a, protocolID, keyID, counterparty: 'self', ciphertext: Uint8Array.from(selfSdk) }), plaintext)
    const message = EncryptedMessage.encrypt(Array.from(plaintext), PrivateKey.fromHex(a), PrivateKey.fromHex(b).toPublicKey())
    assert.deepEqual(brc78Decrypt(Uint8Array.from(message), b), plaintext)
    assert.equal(hex(EncryptedMessage.decrypt(Array.from(brc78Encrypt(plaintext, a, B)), PrivateKey.fromHex(b))), plaintext.toString('hex'))
  }
})

test('LAB_SELF_TEST_ONLY: BRC-39 recipient files written by either side open on the other', async () => {
  for (let i = 0; i < 10; i++) {
    const sender = scalar(), recipient = scalar(), plaintext = Buffer.from(JSON.stringify({ brc: 38, formatVersion: 1, n: randomBytes(16).toString('hex') }))
    const recipientPublic = k42.publicKeyFromPrivate(recipient).toString('hex')
    const file = encryptRecipientFile(plaintext, { senderPrivateKey: sender, recipientPublicKey: recipientPublic })
    const L = file.readUInt16BE(33)
    const K = EncryptedMessage.decrypt(Array.from(file.subarray(35, 35 + L)), PrivateKey.fromHex(recipient))
    const opened = gcm(Uint8Array.from(K), file.subarray(35 + L, 67 + L), file.subarray(0, 35 + L)).decrypt(file.subarray(67 + L))
    assert.deepEqual(Buffer.from(opened), plaintext)
    const K2 = randomBytes(32), nonce = randomBytes(32)
    const wrapped = Buffer.from(EncryptedMessage.encrypt(Array.from(K2), PrivateKey.fromHex(sender), PrivateKey.fromHex(recipient).toPublicKey()))
    const header = Buffer.alloc(35); header.write('WDAT'); header[4] = 2; header[5] = 2; header[6] = 0x26; header[10] = 32; header.writeUInt16BE(wrapped.length, 33)
    const aad = Buffer.concat([header, wrapped])
    const sdkFile = Buffer.concat([aad, nonce, gcm(K2, nonce, aad).encrypt(plaintext)])
    assert.deepEqual(decryptRecipientFile(sdkFile, recipient), plaintext)
  }
})
