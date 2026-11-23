// SDX v0.1 anchoring checker for VA-ANC. Independent laboratory implementation: node builtins
// and the sibling dependency-free modules only.
//
// Two verifiers, one per check the anchoring text gives a reader:
//
// - verifyReference: the ANC §6.1 check of one cross-reference. SDX v0.1 publishes no byte
//   encoding for the reference (the `utxo-chaining` and `cross-domain-refs` suites are not yet
//   published), so the laboratory carries it as the deterministic CBOR map
//
//     Reference = { "v": 1, "aid": text, "tx": bstr(32), "out": uint, "beef": bstr }
//
//   where `beef` is BEEF V1 (BRC-62) or Atomic BEEF (BRC-95) holding the referenced transaction
//   with its BUMP (BRC-74), `tx` and `out` cite that transaction and output, and `aid` is the
//   action the citation claims. The steps run in the order of ANC §6.1.
//
// - walkChain: the ANC §7.1 walk with the ANC §6.2 chain-integrity check and the ANC §4.2 tip
//   rule. It starts from an origin outpoint the operator published (ANC §4.1) or from the
//   entry of the last processed action, finds the transaction that consumes the current entry,
//   and keeps the output whose commitment key matches the derivation for the record that
//   output carries (ANC §2.3, §3.1). The verifier is a root-holder: it holds the root of each
//   epoch it can read (KEYS §1.10.5).
//
// Records are laboratory stand-ins. A v0.1 record keeps `aid` and `ep` in its header inside the
// outer wrap (ENV §6.1), so a reader obtains them by decrypting it (ENV §14). The stand-in is a
// deterministic CBOR map that carries those two members in clear:
//
//   StandIn = { "proto": "tpnil-sdx-lab-stand-in@0.1.0", "hdr": { "aid": text, "ep": uint }, ... }
//
// decodeStandIn stands in for the reader's envelope decode. Its `proto` is not the profile's
// format identifier, so no stand-in is an SDX record envelope.
//
// Outcomes name the ANC §7.5 dead-letter reason as a class. The class is what an
// implementation under test must match. The `label` beside it is the laboratory's own detail
// and is informative only.

import { createECDH, createHmac, hkdfSync } from 'node:crypto'
import { CborDetError, decode, decodeStrict } from './cbor-det.mjs'
import { ChainDataError, bumpRoot, checkContainer, checkScriptSignature, createHeaderTracker, displayHex, hex, matchDataDropCheckSig, parseBeef, parseScript } from './tx.mjs'

export const STAND_IN_PROTO = 'tpnil-sdx-lab-stand-in@0.1.0'
export const REFERENCE_KEYS = Object.freeze(['v', 'aid', 'tx', 'out', 'beef'])
// ANC §7.5 names five members of its fixed set of reasons and says the set includes them. A
// failure the text gives no named reason for is reported as `unlisted`: the action is
// dead-lettered, and an implementation may use any reason for it.
export const DEAD_LETTER_CLASSES = Object.freeze(['integrity-fail', 'decode-fail', 'key-missing', 'cross-ref-invalid', 'chain-break-timeout', 'unlisted'])

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/
const big = bytes => BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`)
const be32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex')

export class AncError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code)
    this.name = 'AncError'
    this.code = code
  }
}

// ---------------------------------------------------------------- keys (KEYS §1.4.2, §1.8.2; ANC §3.1)

function publicKeyOf(scalar) {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(be32(scalar))
  return ecdh.getPublicKey(null, 'compressed')
}

// KEYS §1.4.2 and §1.4.3: the secp256k1 seed of a 64-byte root, refused when outside [1, n-1].
export function secp256k1Seed(root, label) {
  const ikm = Buffer.from(root)
  if (ikm.length !== 64) throw new AncError('root-length')
  const seed = Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(label, 'ascii'), 32))
  const value = big(seed)
  if (value === 0n || value >= N) throw new AncError('seed-invalid')
  return seed
}

// BRC-42 self-derivation (KEYS §1.8.2 with counterparty 'self'): the shared point is d·(d·G),
// the offset is HMAC-SHA-256 keyed by its compressed encoding over the derivation identifier,
// and the child key is (offset + d)·G. An offset of 0 or at least n is refused, never reduced.
export function selfDerivedPublicKey(seed, derivationIdentifier) {
  const d = big(seed)
  const shared = publicKeyOf((d * d) % N)
  const offset = big(createHmac('sha256', shared).update(derivationIdentifier, 'utf8').digest())
  if (offset === 0n || offset >= N) throw new AncError('scalar-rejected')
  const child = (offset + d) % N
  if (child === 0n) throw new AncError('scalar-rejected')
  return publicKeyOf(child)
}

// The derivation identifier of the ANC §3.1 commitment key under a published deployment
// profile: `<level>-<signing namespace>-<record key path>` (KEYS §1.8.1).
export function commitmentDerivationIdentifier(profile, accountId, runtimeId, aid) {
  const { protocolID } = profile.recordKeyIdentifiers.commitment
  const words = profile.derivation.keyPath.keywords
  const path = `${words.level1}/${accountId}/${words.level2}/${runtimeId}/${words.level3}/${aid}`
  return `${protocolID[0]}-${protocolID[1]}-${path}`
}

export function commitmentKey(profile, root, accountId, runtimeId, aid) {
  return selfDerivedPublicKey(secp256k1Seed(root, profile.derivation.curveLabels.secp256k1), commitmentDerivationIdentifier(profile, accountId, runtimeId, aid))
}

// ---------------------------------------------------------------- the record header (stand-in)

export function decodeStandIn(bytes) {
  let value
  try { value = decode(bytes) } catch (error) {
    if (!(error instanceof CborDetError)) throw error
    return { ok: false, reason: 'record-not-decodable' }
  }
  if (!(value instanceof Map) || value.get('proto') !== STAND_IN_PROTO) return { ok: false, reason: 'record-not-stand-in' }
  const header = value.get('hdr')
  if (!(header instanceof Map)) return { ok: false, reason: 'header-missing' }
  const aid = header.get('aid')
  const ep = header.get('ep')
  if (typeof aid !== 'string' || !ULID.test(aid)) return { ok: false, reason: 'header-aid' }
  if (!Number.isSafeInteger(ep) || ep < 0) return { ok: false, reason: 'header-ep' }
  return { ok: true, aid, ep }
}

// ---------------------------------------------------------------- proofs (ANC §6.1 steps 1-3)

// The transaction a BEEF carries and the status of its merkle path against the verifier's own
// header source: Atomic BEEF names its subject; in BEEF V1 it is the last transaction.
function provedTransaction(beefBytes, tracker) {
  let beef
  try { beef = parseBeef(beefBytes) } catch (error) {
    if (!(error instanceof ChainDataError)) throw error
    if (error.code === 'beef-v2-unsupported') return { status: 'inconclusive', label: 'beef-v2-unsupported' }
    return { status: 'refused', label: 'beef-malformed', detail: error.code }
  }
  const entry = beef.txs.get(beef.atomic ? hex(beef.subject) : beef.order.at(-1))
  const { tx } = entry
  if (tx.raw.length === 64) return { status: 'refused', label: 'block-64-byte-tx', tx } // CVE-2017-12842
  if (entry.bumpIndex === null) return { status: 'refused', label: 'block-no-merkle-path', tx } // step 1
  const bump = beef.bumps[entry.bumpIndex]
  let root
  try { root = bumpRoot(bump, tx.txid) } catch (error) { // step 2
    if (!(error instanceof ChainDataError)) throw error
    return { status: 'refused', label: 'block-path-invalid', detail: error.code, tx }
  }
  // Step 3. A height the header source does not hold is a configuration fault; a root that
  // differs from the header the source holds names a non-canonical chain.
  const header = tracker.headerAt(bump.blockHeight)
  if (!header) return { status: 'inconclusive', label: 'header-range-unknown', tx, height: bump.blockHeight }
  if (!header.merkleRoot.equals(root)) return { status: 'refused', label: 'block-root-mismatch', tx, height: bump.blockHeight }
  return { status: 'proved', tx, height: bump.blockHeight }
}

// ---------------------------------------------------------------- ANC §6.1: one reference

export function decodeReference(bytes) {
  let map
  try { map = decodeStrict(bytes) } catch (error) {
    if (!(error instanceof CborDetError)) throw error
    throw new AncError(error.code === 'non-deterministic' ? 'reference-not-deterministic' : 'reference-malformed', error.code)
  }
  if (!(map instanceof Map) || map.size !== REFERENCE_KEYS.length || ![...map.keys()].every(key => REFERENCE_KEYS.includes(key))) throw new AncError('reference-malformed', 'members')
  const aid = map.get('aid'); const tx = map.get('tx'); const out = map.get('out'); const beef = map.get('beef')
  if (map.get('v') !== 1) throw new AncError('reference-version')
  if (typeof aid !== 'string' || !ULID.test(aid)) throw new AncError('reference-malformed', 'aid')
  if (!(tx instanceof Uint8Array) || tx.byteLength !== 32) throw new AncError('reference-malformed', 'tx')
  if (!Number.isSafeInteger(out) || out < 0) throw new AncError('reference-malformed', 'out')
  if (!(beef instanceof Uint8Array) || beef.byteLength === 0) throw new AncError('reference-malformed', 'beef')
  return { aid, tx: Buffer.from(tx), out, beef: Buffer.from(beef) }
}

const reject = (label, detail) => ({ result: 'REJECT', class: 'cross-ref-invalid', label, ...(detail ? { detail } : {}) })

// `recipient` is true when the verifier can decode the referenced record, which makes it run
// the honest-citation guard of ANC §6.1 (a SHOULD for confidentiality-layer recipients).
export function verifyReference({ reference, tracker, recipient = false }) {
  let decoded
  try { decoded = decodeReference(reference) } catch (error) {
    if (error instanceof AncError) return reject(error.code)
    throw error
  }
  const proved = provedTransaction(decoded.beef, tracker) // steps 1-3
  if (proved.status === 'inconclusive') return { result: 'INCONCLUSIVE', label: proved.label }
  if (proved.status === 'refused') return reject(proved.label, proved.detail)
  if (!decoded.tx.equals(proved.tx.txid)) return reject('txid-mismatch') // step 4
  const output = proved.tx.outputs[decoded.out] // step 5
  if (!output) return reject('output-missing')
  const shape = checkContainer(output.script)
  if (!shape.ok) return reject(shape.reason)
  if (recipient) {
    const header = decodeStandIn(shape.record)
    if (!header.ok) return reject('citation-undecodable', header.reason)
    if (header.aid !== decoded.aid) return reject('citation-mismatch')
  }
  return { result: 'ACCEPT' }
}

// ---------------------------------------------------------------- ANC §7.1: the walk

// The consuming input of a `<data> DROP <key> CHECKSIG` entry, rechecked as defence in depth.
// The transaction is proved mined, so the network has already accepted the spend; a check that
// does not pass here is the checker's limit, reported INCONCLUSIVE, never a chain verdict.
// Either S is accepted (KEYS §1.8.3).
export function recheckSpend(tx, inputIndex, prevOutput) {
  const lock = matchDataDropCheckSig(prevOutput.script)
  if (!lock) return { result: 'INCONCLUSIVE', reason: 'spend-template' }
  const unlock = parseScript(tx.inputs[inputIndex].script)
  if (unlock.malformed || unlock.chunks.length === 0 || unlock.chunks.some(chunk => chunk.data === null)) return { result: 'INCONCLUSIVE', reason: 'spend-unlocking-form' }
  const signature = unlock.chunks.at(-1).data
  return checkScriptSignature({ tx, inputIndex, scriptCode: Buffer.from(prevOutput.script), satoshis: prevOutput.satoshis, signature, publicKey: lock.publicKey, strict: false })
}

const outpointKey = (txid, vout) => `${hex(txid)}:${vout}`

// rows: [{ beef }], the transactions the verifier retrieved (ANC §12.6), each with its merkle
// path. start: { kind: 'origin' | 'last-processed', txid (internal order), vout }. keyring: Map
// of epoch to 64-byte root.
export function walkChain({ profile, accountId, runtimeId, keyring, start, rows, tracker }) {
  const txs = new Map()
  const refused = []
  for (const row of rows) {
    const proved = provedTransaction(row.beef, tracker)
    if (!proved.tx) throw new AncError('suite-row', `a walk row carries no readable transaction (${proved.label})`)
    const key = hex(proved.tx.txid)
    if (txs.has(key)) continue
    txs.set(key, proved)
    if (proved.status === 'refused') refused.push({ txid: displayHex(proved.tx.txid), label: proved.label })
  }
  const usable = [...txs.values()].filter(item => item.status !== 'refused')
  const entryCache = new Map()
  // Whether output `vout` of `tx` is an entry of this chain: a conforming container (ANC §2.1,
  // §2.2) whose record decodes and whose key equals the derivation for the action and epoch
  // the record declares (ANC §6.2).
  const entryOf = (tx, vout) => {
    const cacheKey = outpointKey(tx.txid, vout)
    if (entryCache.has(cacheKey)) return entryCache.get(cacheKey)
    let result
    const output = tx.outputs[vout]
    const shape = output ? checkContainer(output.script) : { ok: false }
    if (!shape.ok) result = { kind: 'not-container' }
    else {
      const header = decodeStandIn(shape.record)
      if (!header.ok) result = { kind: 'decode-fail', label: header.reason }
      else if (!keyring.has(header.ep)) result = { kind: 'key-missing', aid: header.aid, ep: header.ep }
      else {
        const expected = commitmentKey(profile, keyring.get(header.ep), accountId, runtimeId, header.aid)
        result = expected.equals(shape.commitmentKey) ? { kind: 'match', aid: header.aid, ep: header.ep } : { kind: 'mismatch', aid: header.aid, ep: header.ep }
      }
    }
    entryCache.set(cacheKey, result)
    return result
  }
  const isChainEntry = (txid, vout) => {
    const item = txs.get(hex(txid))
    return Boolean(item && item.status !== 'refused' && entryOf(item.tx, vout).kind === 'match')
  }
  const dispatched = []
  const deadLetters = []
  const linked = new Set()
  const deadLetter = (tx, cls, label) => deadLetters.push({ txid: displayHex(tx.txid), class: cls, label })
  const finish = (inconclusive = null) => ({
    result: inconclusive ? 'INCONCLUSIVE' : deadLetters.length ? 'DEAD-LETTERED' : 'COMPLETE',
    ...(inconclusive ? { reason: inconclusive } : {}),
    dispatched,
    tip: current ? { txid: displayHex(current.txid), outputIndex: current.vout } : null,
    deadLetters,
    refused
  })
  const failureClass = evaluations => evaluations.some(e => e.kind === 'key-missing') ? ['key-missing', 'epoch-root-not-held']
    : evaluations.some(e => e.kind === 'decode-fail') ? ['decode-fail', evaluations.find(e => e.kind === 'decode-fail').label]
      : ['integrity-fail', 'no-output-matches']

  let current = null
  const startItem = txs.get(hex(start.txid))
  if (!startItem || startItem.status === 'refused') return finish('start-not-held')
  if (startItem.status === 'inconclusive') return finish(startItem.label)
  if (start.kind === 'origin') {
    // ANC §4.1: the origin is committed under the same per-record derivation as every action.
    const origin = entryOf(startItem.tx, start.vout)
    if (origin.kind !== 'match') {
      const [cls, label] = origin.kind === 'mismatch' || origin.kind === 'not-container' ? ['integrity-fail', 'origin-not-derived'] : failureClass([origin])
      deadLetter(startItem.tx, cls, label)
      return finish()
    }
    dispatched.push(origin.aid)
  } else if (start.kind !== 'last-processed') throw new AncError('suite-start', start.kind)
  current = { txid: startItem.tx.txid, vout: start.vout }
  linked.add(outpointKey(current.txid, current.vout))
  // Entries the start descends from are already processed: follow consumed chain entries back.
  for (let item = startItem; item;) {
    const back = item.tx.inputs.find(input => isChainEntry(input.prevTxid, input.vout) && !linked.has(outpointKey(input.prevTxid, input.vout)))
    if (!back) break
    linked.add(outpointKey(back.prevTxid, back.vout))
    item = txs.get(hex(back.prevTxid))
  }

  for (;;) {
    const consumers = usable.filter(item => item.tx.inputs.some(input => input.prevTxid.equals(current.txid) && input.vout === current.vout))
    if (consumers.length === 0) break // the tip
    if (consumers.length > 1) return finish('consumer-ambiguous')
    const [next] = consumers
    if (next.status === 'inconclusive') return finish(next.label)
    const { tx } = next
    // ANC §4.2: exactly one input consumes a tip of this chain.
    const tipInputs = tx.inputs.filter(input => (input.prevTxid.equals(current.txid) && input.vout === current.vout) || isChainEntry(input.prevTxid, input.vout))
    if (tipInputs.length !== 1) { deadLetter(tx, 'unlisted', 'two-tips-consumed'); return finish() }
    const inputIndex = tx.inputs.indexOf(tipInputs[0])
    const spend = recheckSpend(tx, inputIndex, txs.get(hex(current.txid)).tx.outputs[current.vout])
    if (spend.result !== 'PASS') return finish(`spend-recheck-${spend.reason}`)
    // ANC §7.1 steps 2-4 and §2.3: scan every output and keep the one whose key matches.
    const evaluations = tx.outputs.map((_, vout) => ({ vout, ...entryOf(tx, vout) }))
    const matches = evaluations.filter(e => e.kind === 'match')
    if (matches.length > 1) { deadLetter(tx, 'unlisted', 'two-successors'); return finish() }
    if (matches.length === 0) { deadLetter(tx, ...failureClass(evaluations)); return finish() }
    dispatched.push(matches[0].aid)
    current = { txid: tx.txid, vout: matches[0].vout }
    linked.add(outpointKey(current.txid, current.vout))
  }

  // An entry of this chain that the walk never reached waits for a chain link that does not
  // come. The laboratory reports it as `chain-break-timeout` once the walk over the retrieved
  // rows ends (a laboratory interpretation: the batch verifier has no clock).
  for (const item of usable) {
    if (item.status !== 'proved') continue
    item.tx.outputs.forEach((_, vout) => {
      if (!linked.has(outpointKey(item.tx.txid, vout)) && entryOf(item.tx, vout).kind === 'match') deadLetter(item.tx, 'chain-break-timeout', 'entry-not-linked')
    })
  }
  return finish()
}

// ---------------------------------------------------------------- vector suites

// The verifier's header source: the suite's pinned header list, optionally ending at a height.
export function suiteTracker(suite, through = null) {
  return createHeaderTracker(through === null ? suite.chain.headers : suite.chain.headers.filter(entry => entry.height <= through))
}

// Runs one VA-ANC case and returns the outcome in the shape of the case's `expected`.
export function runSuiteCase(suite, profile, item) {
  const bytes = value => Buffer.from(value, 'hex')
  if (item.verifier === 'reference') {
    return verifyReference({ reference: bytes(item.input.reference), tracker: suiteTracker(suite, item.input.headersThrough ?? null), recipient: item.input.recipient })
  }
  if (item.verifier !== 'walk') throw new AncError('suite-verifier', item.verifier)
  const { input } = item
  const chain = suite.chains[input.chain]
  const keyring = new Map(input.keyring.map(epoch => [epoch, bytes(suite.testKeys.roots.participant[String(epoch)].root)]))
  const rows = input.rows.map(name => ({ beef: bytes(suite.transactions[name].beef) }))
  const startTx = suite.transactions[input.start.transaction]
  return walkChain({
    profile, accountId: chain.accountId, runtimeId: chain.runtimeId, keyring,
    start: { kind: input.start.kind, txid: bytes(startTx.txidDisplay).reverse(), vout: input.start.outputIndex },
    rows, tracker: suiteTracker(suite, input.headersThrough ?? null)
  })
}
