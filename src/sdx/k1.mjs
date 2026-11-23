import { createHash, createHmac } from 'node:crypto'
import { int32 } from './ec-p256.mjs'
import { deriveChildPublicKey, publicKeyFromPrivate, sharedSecretPoint } from './brc42.mjs'
import { checkContainer, evaluateSpend, parseTransaction, sha256d, sighashPreimage } from './tx.mjs'
import {
  SECP256K1, argsFromJson, checkCbor, checkOffsetRange, checkPointRejection, derDecode, ecdsaVerify, equalHex, expect,
  expectRejection, fromHex, header, inputFromJson, loadTestRoots, loadWallets, lowS, operationOf, ownChild, run,
  selectedRoot, signDeterministic, callCase
} from './p256.mjs'

// Independent checker of suite VC-SDX-K1: the secp256k1 operations of the
// `p sdx` module (`k1key`, `k1peer`, `k1sign`), root selection on secp256k1,
// the KEYS §1.12 item 7 range on secp256k1, and their rejections. The module semantics are those of src/sdx/p256.mjs.
// Every BRC-100 getPublicKey result the vectors record is recomputed with the
// laboratory's separate BRC-42 oracle, src/sdx/brc42.mjs, and the transaction
// case with src/sdx/tx.mjs. Node built-ins only; nothing from any generator.
const hex = bytes => Buffer.from(bytes).toString('hex')
const N = SECP256K1.n

// Stock BRC-100 getPublicKey semantics through src/sdx/brc42.mjs, for a wallet whose root is `seed`.
function brc100PublicKey(seed, args) {
  if (args.identityKey === true) return publicKeyFromPrivate(seed)
  return deriveChildPublicKey({ rootPrivateKey: seed, protocolID: args.protocolID, keyID: args.keyID, counterparty: args.counterparty, forSelf: args.forSelf === true })
}
// The BRC-100 call that a `k1key` or `k1peer` request equals (draft §Canonical derivation step 3).
function expectedBrc100Args(operation, input) {
  if (!('path' in input)) return { identityKey: true }
  const match = /^([0-2])-([a-z0-9 ]+)-(.+)$/s.exec(input.path)
  expect(match, 'derivation identifier')
  return { protocolID: [Number(match[1]), match[2]], keyID: match[3], counterparty: input.peer ? hex(input.peer) : 'self', ...(operation === 'k1key' ? { forSelf: true } : {}) }
}

export function checkVcSdxK1(doc) {
  let wallets
  const byId = new Map(doc.cases.map(entry => [entry.id, entry]))
  const checks = {
    header() {
      header(doc, 'VC-SDX-K1', ['K1-01', 'K1-02', 'K1-03', 'K1-04', 'K1-05'], 'src/sdx/k1.mjs')
      loadTestRoots(doc)
      wallets = loadWallets(doc)
    },
    module(entry) {
      const wallet = wallets[entry.wallet]
      checkCbor(entry.request)
      const input = inputFromJson(entry.request.input)
      const operation = operationOf(entry.request)
      expect(['k1key', 'k1peer', 'k1sign'].includes(operation), `secp256k1 operation ${operation}`)
      const root = selectedRoot(wallets, doc, entry)
      const call = (overrides = {}) => wallet.call(entry.request.method, { ...argsFromJson(entry.request.method, entry.request.args), ...overrides })
      const result = call().ciphertext
      equalHex(result, entry.expected.ciphertext, `${operation} result`)
      for (const variant of entry.variants ?? []) equalHex(call(variant).ciphertext, entry.expected.ciphertext, `variant ${JSON.stringify(variant)}`)
      if (entry.sameAs) expect(byId.get(entry.sameAs).expected.ciphertext === entry.expected.ciphertext, `same as ${entry.sameAs}`)
      if (entry.differsFrom) expect(byId.get(entry.differsFrom).expected.ciphertext !== entry.expected.ciphertext, `differs from ${entry.differsFrom}`)
      const known = entry.intermediate
      if ('path' in input) {
        const counterparty = input.peer ?? root.K
        const shared = sharedSecretPoint(root.secp256k1Seed, counterparty)
        equalHex(shared, known.sharedPoint, 'shared point (src/sdx/brc42.mjs)')
        equalHex(createHmac('sha256', shared).update(input.path, 'utf8').digest(), known.hmac, 'HMAC')
        if (known.childPrivate) equalHex(int32(ownChild(root.k, counterparty, input.path, SECP256K1).childPrivate), known.childPrivate, 'child private key')
      } else {
        expect(known === undefined, 'no intermediates without a path')
        equalHex(root.K, entry.expected.ciphertext, 'K = secp256k1_seed·G')
      }
      if (operation === 'k1sign') return checkSignature(entry, root, input, result)
      // Equality with stock BRC-100 getPublicKey, recomputed by the separate BRC-42 oracle.
      expect(entry.brc100.method === 'getPublicKey' && JSON.stringify(entry.brc100.args) === JSON.stringify(expectedBrc100Args(operation, input)), 'the BRC-100 call this request equals')
      equalHex(brc100PublicKey(root.secp256k1Seed, entry.brc100.args), entry.brc100.publicKey, 'BRC-100 getPublicKey (src/sdx/brc42.mjs)')
      expect(entry.brc100.publicKey === entry.expected.ciphertext, 'the module result equals stock BRC-100')
    },
    'offset-range'(entry) {
      expect(entry.curve === 'secp256k1' && entry.injected === true, 'secp256k1 values, injected')
      checkOffsetRange(entry)
    },
    'point-rejection'(entry) { checkPointRejection(entry, wallets, 3) },
    'request-rejection'(entry) {
      checkCbor(entry.request)
      expectRejection(() => callCase(wallets[entry.wallet], entry.request), entry.expected.error)
    },
    behaviour(entry) {
      expect(['given', 'when', 'then'].every(name => typeof entry[name] === 'string' && entry[name].length), 'behaviour text')
      return 'behavioural'
    }
  }
  function checkSignature(entry, root, input, signature) {
    const known = entry.intermediate
    const counterparty = input.peer ?? root.K
    const child = ownChild(root.k, counterparty, input.path, SECP256K1)
    equalHex(child.publicKey, known.publicKey, 'signing child public key')
    const { r, s } = derDecode(signature)
    expect(s <= N / 2n, 'low-S')
    expect(ecdsaVerify(SECP256K1, child.publicKey, input.hash, r, s), 'ECDSA verification over hash as given')
    expect(!ecdsaVerify(SECP256K1, child.publicKey, createHash('sha256').update(input.hash).digest(), r, s), 'the hash is not hashed again')
    const raw = signDeterministic(child.childPrivate, input.hash, SECP256K1)
    equalHex(Buffer.concat([int32(raw.r), int32(raw.s)]), known.rfc6979, 'RFC 6979 signature before low-S')
    expect(raw.r === r && lowS(raw.s, SECP256K1) === s, 'low-S form of the RFC 6979 signature')
    expect((raw.s > N / 2n) === known.normalised, 'normalised flag')
    const { brc100 } = entry
    const match = /^([0-2])-([a-z0-9 ]+)-(.+)$/s.exec(input.path)
    expect(brc100.method === 'createSignature' && brc100.args.hashToDirectlySign === hex(input.hash) && JSON.stringify(brc100.args.protocolID) === JSON.stringify([Number(match[1]), match[2]]) &&
      brc100.args.keyID === match[3] && brc100.args.counterparty === (input.peer ? hex(input.peer) : 'self'), 'the BRC-100 call this request equals')
    expect(brc100.signature === entry.expected.ciphertext, 'k1sign equals stock BRC-100 createSignature')
    if (entry.transaction) checkTransaction(entry, input, signature)
  }
  // The commitment spend: the record output, the preimage, and the spend itself.
  function checkTransaction(entry, input, signature) {
    const { transaction } = entry
    const previous = parseTransaction(fromHex(transaction.previous))
    const spending = parseTransaction(fromHex(transaction.spending))
    const spent = spending.inputs[transaction.inputIndex]
    expect(spent.prevTxid.equals(previous.txid) && spent.vout === 0, 'input spends output 0 of the previous transaction')
    const tip = previous.outputs[0]
    const shape = checkContainer(tip.script)
    expect(shape.ok, `ANC §2.1 container: ${shape.reason}`)
    equalHex(shape.commitmentKey, byId.get('k1key-commitment-key').expected.ciphertext, 'the container holds the commitment key k1key returns')
    const preimage = sighashPreimage(spending, transaction.inputIndex, tip.script, tip.satoshis, transaction.sighashType)
    equalHex(preimage, transaction.preimage, 'BIP-143 preimage')
    equalHex(sha256d(preimage), hex(input.hash), '`hash` is SHA-256d of the preimage')
    expect(spent.script.subarray(1).equals(Buffer.concat([signature, Buffer.from([transaction.sighashType])])) && spent.script[0] === signature.length + 1, 'unlocking script pushes the k1sign result and the sighash byte')
    const outcome = evaluateSpend({ tx: spending, inputIndex: transaction.inputIndex, prevTxid: previous.txid, prevOut: 0, prevOutput: tip })
    expect(outcome.result === 'PASS', `spend evaluation: ${outcome.result} ${outcome.reason}`)
  }
  return run(doc, checks)
}
