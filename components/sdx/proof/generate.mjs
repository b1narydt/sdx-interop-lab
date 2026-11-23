#!/usr/bin/env node
// Generates the SDX v0.1 encoding and anchoring vector suites VA-ENC and VA-ANC.
//
//   node generate.mjs --write   regenerate fixtures/sdx/v1/{va-enc,va-anc}/vectors.json
//   node generate.mjs --check   regenerate in memory and compare with the committed files
//
// Each case's expected outcome is declared here from the way the case is constructed. The
// generator then runs the dependency-free checker (src/sdx) and @bsv/sdk over the cases and
// stops on any disagreement. Output is deterministic: RFC 6979 signatures, fixed keys and
// roots, fixed synthetic times and a nonce search from zero.

import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { Beef, BEEF_V2, MerklePath, Spend, Transaction } from '@bsv/sdk'
import { ACCOUNT_ID, CHAINS, STAND_IN_BODY, STAND_IN_PROTO, buildWorld, txid } from './lib/world.mjs'
import { ROOT_LABEL_PREFIX, describeKeys } from './lib/keys.mjs'
import { BITS, BLOCK_SPACING, COINBASE_LABEL, GENESIS_TIME, display } from './lib/chain.mjs'
import { agreement, cborg, cborgDecode, det, insertionOrder } from './lib/cbor.mjs'
import { atomicBeef, beefV1 } from './lib/beef.mjs'
import { DEAD_LETTER_CLASSES, commitmentKey, suiteTracker, verifyReference, walkChain } from '../../../src/sdx/anc.mjs'
import { createHeaderTracker, sha256 } from '../../../src/sdx/tx.mjs'
import { decode as labDecode, decodeStrict as labDecodeStrict, encode as labEncode } from '../../../src/sdx/cbor-det.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '../../..')
const PACKAGE = JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8'))
const PROFILE_PATH = 'fixtures/sdx/v1/deployment-profile.json'
const PROFILE_BYTES = fs.readFileSync(path.join(ROOT, PROFILE_PATH))
const PROFILE = JSON.parse(PROFILE_BYTES)
const H = bytes => Buffer.from(bytes).toString('hex')

const TEXT = {
  anc: 'fixtures/sdx/v1/standards/text/anchoring.md',
  env: 'fixtures/sdx/v1/standards/text/envelope.md',
  keys: 'fixtures/sdx/v1/standards/text/keys.md',
  base: 'fixtures/sdx/v1/standards/text/base.md',
  vec: 'fixtures/sdx/v1/standards/text/vectors.md',
  suites: 'fixtures/sdx/v1/standards/cbor-det-v1/index.json'
}
const REFERENCES = {
  'BRC-62': { title: 'Background Evaluation Extended Format (BEEF) Transactions', url: 'https://github.com/bsv-blockchain/BRCs/blob/master/transactions/0062.md' },
  'BRC-74': { title: 'BSV Unified Merkle Path (BUMP) Format', url: 'https://github.com/bsv-blockchain/BRCs/blob/master/transactions/0074.md' },
  'BRC-95': { title: 'Atomic BEEF Transactions', url: 'https://github.com/bsv-blockchain/BRCs/blob/master/transactions/0095.md' },
  'BRC-42': { title: 'BSV Key Derivation Scheme (BKDS)', url: 'https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0042.md' },
  'RFC 5869': { title: 'HMAC-based Extract-and-Expand Key Derivation Function (HKDF)', url: 'https://www.rfc-editor.org/rfc/rfc5869' },
  'RFC 8949': { title: 'Concise Binary Object Representation (CBOR), §4.2.1 Core Deterministic Encoding Requirements', url: 'https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1' }
}
const references = ids => ids.map(id => ({ id, ...REFERENCES[id] }))

const GENERATOR = {
  component: 'components/sdx/proof',
  command: 'npm run generate --prefix components/sdx/proof',
  check: 'npm run check --prefix components/sdx/proof',
  dependencies: PACKAGE.dependencies,
  lockfile: 'components/sdx/proof/package-lock.json',
  deterministic: 'Fixed public test keys and roots, RFC 6979 signatures, fixed synthetic header times and a proof-of-work nonce search from zero; two runs produce identical files.'
}

// ------------------------------------------------------------------ decisions

const BASIS = 'Rests on the cited text'
const READING = 'Laboratory interpretation'
const CHOICE = 'Laboratory test-construction choice'
const DECISIONS = {
  profile: { id: 'deployment-profile', kind: BASIS, text: `Every derived value follows the laboratory deployment profile \`${PROFILE.profile}\` (${PROFILE_PATH}; KEYS §1.3.1, ENV §2.1). The commitment key of an action is the BRC-42 self-derivation, on the secp256k1 seed of the root of the epoch the record declares (KEYS §1.4.2, HKDF-SHA-256 with info \`${PROFILE.derivation.curveLabels.secp256k1}\`), under protocol [2, \`${PROFILE.recordKeyIdentifiers.commitment.protocolID[1]}\`] with key ID \`account/<accountId>/runtime/<runtimeId>/action/<actionId>\` (ANC §3.1; KEYS §1.6.1, §1.8.1, §1.8.2). The level-3 keyword \`action\` is the profile's reading R1.` },
  verifierHoldsRoots: { id: 'root-holding-reader', kind: BASIS, text: 'The walk runs as the participant\'s own reader, which ANC §6.2 requires to perform the chain-integrity check. It holds the participant\'s root for each epoch it can read (its keyring, KEYS §1.10.5), and each case states which epochs it holds. The roots are public 64-byte test values, published in `testKeys.roots`; they control 1-satoshi entries on the synthetic chain only.' },
  standIn: { id: 'stand-in-records', kind: CHOICE, text: `Records are stand-ins: deterministic CBOR maps {proto: "${STAND_IN_PROTO}", hdr: {aid, ep}, body} that carry in clear the two header members ANC §6.2 step 3 reads. A v0.1 record keeps them inside its outer wrap (ENV §6.1), and a reader obtains them by decrypting it (ENV §14). The stand-in's decode replaces that step: a stand-in decodes when it is a map with that proto and a header whose \`aid\` has ULID grammar and whose \`ep\` is an unsigned integer. The stand-in proto is not the profile's format identifier, so no stand-in is an SDX record envelope. Envelopes are the subject of VA-ENV (not yet authored).` },
  reference: { id: 'reference-encoding', kind: CHOICE, text: 'SDX v0.1 publishes no byte encoding for a reference and its proof (the `utxo-chaining` and `cross-domain-refs` suites are not yet published). The suite carries a reference as the deterministic CBOR map {v: 1, aid, tx, out, beef}: `beef` is BEEF V1 or Atomic BEEF holding the referenced transaction with its merkle path, `tx` and `out` cite that transaction and output (ANC §6.1 steps 4 and 5), and `aid` is the action the citation claims. The map is decoded strictly, beyond the semantic decoder ENV §3 requires, and a map with missing or additional members is refused. VA-ANC is re-based on the SDX suites when SDX publishes them.' },
  referenceSteps: { id: 'reference-steps', kind: BASIS, text: 'verifyReference runs the steps of ANC §6.1 in order. Step 1 takes the transaction the proof carries (the Atomic BEEF subject, or the last transaction of BEEF V1) and its BUMP; step 2 computes the Bitcoin SHA-256d merkle root for the transaction\'s computed txid; step 3 confirms the root against the verifier\'s header source; step 4 confirms the cited txid equals the computed one; step 5 confirms the cited output exists and has the container shape of ANC §2.1 and §2.2. A transaction of exactly 64 bytes is not accepted as proved mined (CVE-2017-12842). Any failure is the dead-letter class `cross-ref-invalid` (ANC §6.1, §7.5). The BRC-74 client-txid flag (0x02) is informational, as in @bsv/sdk, so it is the one bit of a BUMP leaf a proof does not bind.' },
  headerSource: { id: 'header-source', kind: BASIS, text: 'ANC §6.1 step 3 names two causes for a root the verifier cannot confirm. A block height its header source does not hold is a configuration fault: the outcome is INCONCLUSIVE, with label `header-range-unknown`. A root that differs from the header the source holds at that height names a non-canonical chain: the reference is refused, and in a walk the row is refused.' },
  honestCitation: { id: 'honest-citation', kind: BASIS, text: 'A verifier that is a recipient of the referenced record SHOULD decode it and confirm its header declares the chain and action the citation claims (ANC §6.1). Cases with `recipient: true` run that guard and compare the referenced record\'s `aid` with the claimed `aid`. A verifier that is not a recipient cannot run it and accepts any valid container at the cited position, which the paired cases show. The chain half of the guard is not checked: the ENV §6.1 header declares no chain (coverage source finding ANC-6).' },
  walk: { id: 'walk', kind: BASIS, text: 'walkChain starts from the origin outpoint the operator published (ANC §4.1) or from the entry of the last processed action (ANC §7.1). It proves each retrieved transaction through its merkle path against its header source (ANC §12.6, §16) and does not use a refused one. It then repeats ANC §7.1: find the transaction that consumes the current entry; require exactly one of its inputs to consume a tip of this chain (ANC §4.2); scan every output, decode each container (ANC §2.1, §2.2) and its record, derive the expected commitment key for the action and epoch the record declares, and keep the output whose key matches (ANC §2.3, §6.2); move to it. An origin start first checks the origin entry the same way (ANC §4.1). Canonical order is spend order (ANC §7.2): two actions in one block are ordered by their spend.' },
  spendRecheck: { id: 'spend-recheck', kind: BASIS, text: 'The consuming input is rechecked as defence in depth: `<record> DROP <key> CHECKSIG` with a SIGHASH_FORKID signature (BIP 143 preimage), verified as secp256k1 ECDSA over SHA-256d. Either S is accepted (KEYS §1.8.3). The transaction is proved mined, so a recheck that does not pass is the checker\'s limit: the walk stops INCONCLUSIVE, and never reports a chain verdict from it.' },
  classes: { id: 'dead-letter-classes', kind: BASIS, text: 'Outcomes name the ANC §7.5 dead-letter reason as a class: `integrity-fail` (no output matches, ANC §6.2 and §7.1 step 4; or an origin entry that is not the participant\'s derivation), `decode-fail` (a record that does not decode), `key-missing` (a record that declares an epoch whose root the reader does not hold; KEYS §1.10.4 has it halt rather than skip), `cross-ref-invalid` (a reference that fails ANC §6.1), and `chain-break-timeout`. ANC §7.5 says the fixed set includes these five and lists no others, so a failure the text names no reason for, such as an action that consumes two tips (ANC §4.2), is the class `unlisted`: the action is dead-lettered and any reason is accepted. An implementation under test must match the result, the dispatched actions, the tip, the class of each dead-lettered transaction and the set of refused transactions. Every `label` is the laboratory\'s own detail and is informative only.' },
  halts: { id: 'walk-halts', kind: READING, text: 'The walk halts at the first dead-lettered action and dispatches nothing after it. ANC §6.1 forbids dispatching a partially verified action; v0.1 does not say whether a reader walks past a dead-lettered one.' },
  precedence: { id: 'no-match-reason', kind: READING, text: 'When no output of the consuming transaction matches, ANC §7.1 step 4 names `integrity-fail`. Where a candidate\'s derivation could not be attempted, the walk reports the reason that stopped it instead: `key-missing` first (KEYS §1.10.4), then `decode-fail`.' },
  timeout: { id: 'unlinked-entries', kind: READING, text: 'An entry of the chain that no walk from the start reaches waits for a chain link that does not arrive. A reader with a clock dead-letters it as `chain-break-timeout` when its wait ends (ANC §7.5); the suite\'s verifier has no clock, so it reports each such entry once the walk over the retrieved rows ends normally. Entries the start descends from count as processed.' },
  origin: { id: 'origin', kind: BASIS, text: 'The walk does not read an origin marker. ANC §4.1 places one in the origin\'s envelope header, but the ENV §6.1 header defines no such member (coverage source finding ANC-4). A consumer follows a chain from the origin identifier the operator published out of band (ANC §4.1), so a competing entry elsewhere does not change the walk. The forged origin in this suite carries the participant\'s origin record under a key from another root.' },
  byteOrder: { id: 'byte-order', kind: CHOICE, text: 'Inside proofs, BEEF and BUMPs, every txid and merkle node is in internal byte order (the raw SHA-256d output). Outpoints and txids in the JSON fields `txidDisplay`, `tip` and `deadLetters` use display order, the reverse, as transaction identifiers are written in index answers; ANC §12.2 writes only `<hex>`.' },
  syntheticChain: { id: 'synthetic-chain', kind: CHOICE, text: 'The pinned list of synthetic 80-byte block headers in `chain.headers` is the header source. Each header meets its own regtest-difficulty bits (0x207fffff) and links to its predecessor. Height 0 holds the synthetic genesis coinbase that funds every transaction; heights 1-100 hold coinbase-only blocks so that the genesis coinbase is mature when it is spent at height 101. A case with `headersThrough` gives the verifier the list up to that height only. Every transaction is valid; none is broadcast or touches any network.' },
  beef: { id: 'beef-profile', kind: CHOICE, text: 'Proof BEEF is BEEF V1 (BRC-62) or Atomic BEEF (BRC-95) wrapping V1. Every transaction appears once and after any in-BEEF parent; each BUMP reference names a BUMP that holds the txid at level 0; an Atomic BEEF holds its subject and only the subject\'s in-BEEF ancestors. BEEF V2 is recognised and reported INCONCLUSIVE.' },
  scope: { id: 'scope', kind: BASIS, text: 'Outside this suite: the write path (ANC §5), rotation (ANC §4.3; VA-ROT is not yet authored), reorganisation (ANC §7.4), and admission and the per-topic index (ANC §10-§16). ANC §2.4 is a writer obligation: every entry here carries the profile\'s value floor of one satoshi, and no verifier check rests on it.' }
}

// ------------------------------------------------------------------ helpers

function assertStrictJson(value, where = '$') {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(`${where}: non-integer number`)
  if (Array.isArray(value)) value.forEach((item, i) => assertStrictJson(item, `${where}[${i}]`))
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) assertStrictJson(v, `${where}.${k}`)
}

const same = (id, actual, expected) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${id}: checker gave ${JSON.stringify(actual)}, construction declares ${JSON.stringify(expected)}`)
}
const pad = n => String(n).padStart(3, '0')

// ------------------------------------------------------------------ world and oracles

const world = await buildWorld(PROFILE)
const tracker = createHeaderTracker(world.chain.headerList())
const sdkTracker = world.chain.sdkTracker()
const oracle = { spendsValid: 0, merklePaths: 0, beefValid: 0, atomicParsed: 0, cborgDecoded: 0, commitmentKeys: 0, checkerCases: 0 }
const T = world.transactions
const A = world.actions

const rawOf = tx => Buffer.from(tx.toBinary())
const bumpOf = tx => { const merklePath = world.chain.pathOf(tx); if (!merklePath) throw new Error('transaction is not mined'); return Buffer.from(merklePath.toBinary()) }
const mined = tx => ({ raw: rawOf(tx), bump: bumpOf(tx) })
const loose = tx => ({ raw: rawOf(tx), bump: null })
const heightOf = tx => world.chain.located.get(H(txid(tx))).height

// One bit of the highest stored sibling hash of a transaction's BUMP, changed.
function alteredBump(tx) {
  const merklePath = MerklePath.fromBinary([...bumpOf(tx)])
  const level = merklePath.path.findLastIndex(leaves => leaves.some(leaf => leaf.hash && !leaf.txid))
  const leaf = merklePath.path[level].find(l => l.hash && !l.txid)
  const bytes = Buffer.from(leaf.hash, 'hex'); bytes[0] ^= 0x01
  leaf.hash = bytes.toString('hex')
  return Buffer.from(merklePath.toBinary())
}

function sdkSpendValid(tx, inputIndex, prevTx, vout) {
  const input = tx.inputs[inputIndex]
  const output = prevTx.outputs[vout]
  try {
    return new Spend({
      sourceTXID: prevTx.id('hex'), sourceOutputIndex: vout, sourceSatoshis: output.satoshis, lockingScript: output.lockingScript,
      transactionVersion: tx.version, otherInputs: tx.inputs.filter((_, i) => i !== inputIndex), outputs: tx.outputs,
      inputIndex, unlockingScript: input.unlockingScript, inputSequence: input.sequence, lockTime: tx.lockTime
    }).validate() === true
  } catch { return false }
}

for (const tx of world.all) {
  tx.inputs.forEach((input, i) => {
    if (!sdkSpendValid(tx, i, input.sourceTransaction, input.sourceOutputIndex)) throw new Error(`@bsv/sdk Spend rejects input ${i} of ${tx.id('hex')}`)
    oracle.spendsValid++
  })
}
for (const block of world.chain.blocks.slice(101)) {
  for (const tx of block.txs.slice(1)) {
    const merklePath = world.chain.pathOf(tx)
    if (merklePath.computeRoot(tx.id('hex')) !== display(block.merkleRoot) || !(await merklePath.verify(tx.id('hex'), sdkTracker))) throw new Error('@bsv/sdk MerklePath disagrees')
    oracle.merklePaths++
  }
}
// Every participant commitment key @bsv/sdk derived (PushDrop, KeyDeriver) equals the
// checker's node:crypto derivation from the published root.
for (const c of world.commitments.filter(item => item.holder === 'participant')) {
  const fromChecker = commitmentKey(PROFILE, world.roots.participant[c.ep].root, ACCOUNT_ID, CHAINS[c.runtime].runtimeId, c.aid)
  if (H(fromChecker) !== c.publicKey) throw new Error(`commitment key of ${c.runtime}/${c.aid}: checker ${H(fromChecker)}, @bsv/sdk ${c.publicKey}`)
  oracle.commitmentKeys++
}

async function sdkBeefValid(beef) {
  if (beef.subarray(0, 4).toString('hex') === '01010101') {
    if (Transaction.fromAtomicBEEF([...beef]).id('hex') !== display(beef.subarray(4, 36))) throw new Error('@bsv/sdk Atomic BEEF subject mismatch')
    oracle.atomicParsed++
  }
  const parsed = Beef.fromBinary([...beef])
  if (!parsed.isValid(false) || !(await parsed.verify(sdkTracker, false))) throw new Error('@bsv/sdk rejects a BEEF the checker proves')
  oracle.beefValid++
}

// ------------------------------------------------------------------ VA-ANC: transactions

// Walk rows: each transaction in Atomic BEEF with its BUMP, as an index answer carries it.
const rowTable = {}
const row = (name, tx, beef = atomicBeef(txid(tx), beefV1([mined(tx)]))) => {
  rowTable[name] = { txidDisplay: tx.id('hex'), height: heightOf(tx), entryOutput: world.containers[name] ?? null, beef: H(beef) }
}
for (const [name, tx] of Object.entries(T)) row(name, tx)
row('M3-bump-altered', T.M3, atomicBeef(txid(T.M3), beefV1([{ raw: rawOf(T.M3), bump: alteredBump(T.M3) }])))
rowTable['M3-bump-altered'].entryOutput = 1
for (const [name, entry] of Object.entries(rowTable)) if (name !== 'M3-bump-altered') await sdkBeefValid(Buffer.from(entry.beef, 'hex'))

// ------------------------------------------------------------------ VA-ANC: cases

const A07 = 'SDX-A-07'
const cases = []
const suiteView = () => ({ chain: { headers: world.chain.headerList() }, chains: chainTable(), roots: rootTable(), transactions: rowTable })

// The reference map (decision reference-encoding).
const referenceBytes = ({ aid, tx, out, beef }) => det({ v: 1, aid, tx: txid(tx), out, beef })
const atomicOf = tx => atomicBeef(txid(tx), beefV1([mined(tx)]))
const accept = { result: 'ACCEPT' }
const refused = label => ({ result: 'REJECT', class: 'cross-ref-invalid', label })

async function referenceCase({ id, description, reference, recipient = false, headersThrough, expected }) {
  const caseTracker = headersThrough === undefined ? tracker : suiteTracker({ chain: { headers: world.chain.headerList() } }, headersThrough)
  const got = verifyReference({ reference, tracker: caseTracker, recipient })
  same(id, { result: got.result, ...(got.class ? { class: got.class } : {}), ...(got.label ? { label: got.label } : {}) }, expected)
  oracle.checkerCases++
  if (expected.result === 'ACCEPT') {
    oracle.cborgDecoded++
    await sdkBeefValid(Buffer.from(cborgDecode(reference).get('beef')))
  }
  cases.push({ id, requirement: A07, description, verifier: 'reference', input: { reference: H(reference), recipient, ...(headersThrough !== undefined ? { headersThrough } : {}) }, expected })
}

const tipOf = (name, output = world.containers[name]) => ({ txid: T[name].id('hex'), outputIndex: output })
const letter = (name, cls, label) => ({ txid: T[name].id('hex'), class: cls, label })
const aids = names => names.map(name => A[name].aid)

function walkCase({ id, description, chain, keyring = [0, 1], start, rows, headersThrough, expected }) {
  const input = { chain, keyring, start, rows, ...(headersThrough !== undefined ? { headersThrough } : {}) }
  const view = suiteView()
  const got = walkChain({
    profile: PROFILE, accountId: ACCOUNT_ID, runtimeId: CHAINS[chain].runtimeId,
    keyring: new Map(keyring.map(ep => [ep, world.roots.participant[ep].root])),
    start: { kind: start.kind, txid: Buffer.from(view.transactions[start.transaction].txidDisplay, 'hex').reverse(), vout: start.outputIndex },
    rows: rows.map(name => ({ beef: Buffer.from(view.transactions[name].beef, 'hex') })),
    tracker: headersThrough === undefined ? tracker : suiteTracker(view, headersThrough)
  })
  const full = { refused: [], deadLetters: [], ...expected }
  const want = { result: full.result, ...(full.reason ? { reason: full.reason } : {}), dispatched: full.dispatched, tip: full.tip, deadLetters: full.deadLetters, refused: full.refused }
  same(id, got, want)
  oracle.checkerCases++
  cases.push({ id, requirement: A07, description, verifier: 'walk', input, expected: want })
}

const origin = name => ({ kind: 'origin', transaction: name, outputIndex: world.containers[name] })
const after = name => ({ kind: 'last-processed', transaction: name, outputIndex: world.containers[name] })
const M_ROWS = ['M0', 'M1', 'M2', 'M3', 'M4']
const M_ALL = { result: 'COMPLETE', dispatched: aids(['M0', 'M1', 'M2', 'M3', 'M4']), tip: tipOf('M4') }

// ANC §6.1: references.
await referenceCase({ id: 'VA-ANC-001', description: 'A reference to action M1 in Atomic BEEF, checked by a verifier that is not a recipient of M1: steps 1-5 of ANC §6.1 hold.', reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 0, beef: atomicOf(T.M1) }), expected: accept })
await referenceCase({ id: 'VA-ANC-002', description: 'A reference to action M2 in BEEF V1, checked by a recipient: M2\'s entry is output 1 (ANC §2.3), and its record declares the action the citation claims.', reference: referenceBytes({ aid: A.M2.aid, tx: T.M2, out: 1, beef: beefV1([mined(T.M2)]) }), recipient: true, expected: accept })
await referenceCase({ id: 'VA-ANC-003', description: 'A reference to action M3, whose transaction also carries a handoff entry (ANC §3.4) at output 0, checked by a recipient.', reference: referenceBytes({ aid: A.M3.aid, tx: T.M3, out: 1, beef: atomicOf(T.M3) }), recipient: true, expected: accept })
await referenceCase({ id: 'VA-ANC-004', description: 'A citation that labels M3\'s handoff entry (output 0) as action M3, checked by a recipient: the record there declares another action (honest-citation guard, ANC §6.1).', reference: referenceBytes({ aid: A.M3.aid, tx: T.M3, out: 0, beef: atomicOf(T.M3) }), recipient: true, expected: refused('citation-mismatch') })
await referenceCase({ id: 'VA-ANC-005', description: 'The citation of VA-ANC-004 checked by a verifier that is not a recipient: it can confirm only that a valid container exists at the cited position, so it accepts (ANC §6.1).', reference: referenceBytes({ aid: A.M3.aid, tx: T.M3, out: 0, beef: atomicOf(T.M3) }), expected: accept })
await referenceCase({ id: 'VA-ANC-006', description: 'BUMP for the wrong root: one bit of the highest stored sibling hash changed. The header source holds that height with a different root, so the proof names a non-canonical chain (ANC §6.1 step 3).', reference: referenceBytes({ aid: A.M2.aid, tx: T.M2, out: 1, beef: beefV1([{ raw: rawOf(T.M2), bump: alteredBump(T.M2) }]) }), expected: refused('block-root-mismatch') })
{
  const bump = bumpOf(T.M1)
  if (bump[0] !== heightOf(T.M1)) throw new Error('unexpected BUMP height encoding')
  const lower = Buffer.from(bump); lower[0] = bump[0] - 1
  await referenceCase({ id: 'VA-ANC-007', description: `M1's BUMP with its block height changed from ${bump[0]} to ${bump[0] - 1}: the header source holds height ${bump[0] - 1}, and its root differs (ANC §6.1 step 3).`, reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 0, beef: beefV1([{ raw: rawOf(T.M1), bump: lower }]) }), expected: refused('block-root-mismatch') })
  await referenceCase({ id: 'VA-ANC-008', description: `A reference to M1 checked by a verifier whose header source ends at height ${bump[0] - 1}: the range is unknown to it, a configuration fault rather than an attack (ANC §6.1 step 3).`, reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 0, beef: atomicOf(T.M1) }), headersThrough: bump[0] - 1, expected: { result: 'INCONCLUSIVE', label: 'header-range-unknown' } })
}
await referenceCase({ id: 'VA-ANC-009', description: 'A reference whose cited txid is M2\'s while the BEEF carries M1: the cited identifier is not the one computed from the supplied bytes (ANC §6.1 step 4).', reference: referenceBytes({ aid: A.M1.aid, tx: T.M2, out: 0, beef: atomicOf(T.M1) }), expected: refused('txid-mismatch') })
await referenceCase({ id: 'VA-ANC-010', description: 'A reference whose BEEF carries M1 without a merkle path (ANC §6.1 step 1).', reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 0, beef: beefV1([loose(T.M1)]) }), expected: refused('block-no-merkle-path') })
{
  const v2 = new Beef(BEEF_V2)
  v2.mergeRawTx([...rawOf(T.M1)], v2.mergeBump(world.chain.pathOf(T.M1)))
  await referenceCase({ id: 'VA-ANC-011', description: 'A reference whose proof is BEEF version 2 (0200BEEF, BRC-96), written by @bsv/sdk. This checker reads BEEF V1 and Atomic BEEF only.', reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 0, beef: Buffer.from(v2.toBinary()) }), expected: { result: 'INCONCLUSIVE', label: 'beef-v2-unsupported' } })
}
await referenceCase({ id: 'VA-ANC-012', description: 'A reference citing output 2 of M1, which has two outputs (ANC §6.1 step 5).', reference: referenceBytes({ aid: A.M1.aid, tx: T.M1, out: 2, beef: atomicOf(T.M1) }), expected: refused('output-missing') })
await referenceCase({ id: 'VA-ANC-013', description: 'A reference citing output 0 of M2, its P2PKH change, which does not have the container shape (ANC §6.1 step 5, ANC §2.1).', reference: referenceBytes({ aid: A.M2.aid, tx: T.M2, out: 0, beef: atomicOf(T.M2) }), expected: refused('container-template') })
await referenceCase({ id: 'VA-ANC-014', description: 'A reference to a mined container whose record push uses OP_PUSHDATA1 where a direct push is the minimal opcode (ANC §2.1).', reference: referenceBytes({ aid: A.NM.aid, tx: T.NM, out: 0, beef: atomicOf(T.NM) }), expected: refused('container-push-not-minimal') })
await referenceCase({ id: 'VA-ANC-015', description: 'A reference to a mined container with two data fields, `<record> <extra> 2DROP <key> CHECKSIG`; ANC §2.2 requires exactly one.', reference: referenceBytes({ aid: A.TF.aid, tx: T.TF, out: 0, beef: atomicOf(T.TF) }), expected: refused('container-field-count') })
await referenceCase({ id: 'VA-ANC-016', description: 'The reference of VA-ANC-001 with its map members in insertion order (v, aid, tx, out, beef) rather than the deterministic order. Refusing it is a laboratory choice (decision reference-encoding).', reference: insertionOrder({ v: 1, aid: A.M1.aid, tx: txid(T.M1), out: 0, beef: atomicOf(T.M1) }), expected: refused('reference-not-deterministic') })

// ANC §7.1: walks.
walkCase({ id: 'VA-ANC-017', description: 'Chain M walked from its origin. M2\'s entry is output 1; M2 and M3 share a block and are ordered by spend (ANC §7.2); M3 consumes the tip with input 0 and carries a handoff entry before its own (ANC §2.3, §3.4); M4 is a version-2 transaction whose consuming signature is high-S (KEYS §1.8.3).', chain: 'M', start: origin('M0'), rows: M_ROWS, expected: M_ALL })
walkCase({ id: 'VA-ANC-018', description: 'Chain M walked from the entry of M2, the last action the reader processed (ANC §7.1).', chain: 'M', start: after('M2'), rows: M_ROWS, expected: { result: 'COMPLETE', dispatched: aids(['M3', 'M4']), tip: tipOf('M4') } })
walkCase({ id: 'VA-ANC-019', description: 'Chain M walked from the entry of M4, the tip: nothing new to dispatch.', chain: 'M', start: after('M4'), rows: M_ROWS, expected: { result: 'COMPLETE', dispatched: [], tip: tipOf('M4') } })
walkCase({ id: 'VA-ANC-020', description: 'Chain M from its origin, with a competing origin entry among the rows: the participant\'s origin record committed under a key from another root. The walk follows the published origin, and the competing entry is not an entry of this chain (ANC §4.1, §9).', chain: 'M', start: origin('M0'), rows: [...M_ROWS, 'F'], expected: M_ALL })
walkCase({ id: 'VA-ANC-021', description: 'A walk started from the forged origin entry: its key is not the participant\'s derivation for the action its record declares (ANC §4.1, §6.2).', chain: 'M', start: origin('F'), rows: [...M_ROWS, 'F'], expected: { result: 'DEAD-LETTERED', dispatched: [], tip: null, deadLetters: [letter('F', 'integrity-fail', 'origin-not-derived')] } })
{
  const m4 = heightOf(T.M4)
  walkCase({ id: 'VA-ANC-022', description: `Chain M from its origin for a verifier whose header source ends at height ${m4 - 1}: M4, mined at height ${m4}, cannot be proved, so the walk stops INCONCLUSIVE after M3 (ANC §6.1 step 3, configuration fault).`, chain: 'M', start: origin('M0'), rows: M_ROWS, headersThrough: m4 - 1, expected: { result: 'INCONCLUSIVE', reason: 'header-range-unknown', dispatched: aids(['M0', 'M1', 'M2', 'M3']), tip: tipOf('M3') } })
}
walkCase({ id: 'VA-ANC-023', description: 'Chain M from its origin, with M3 answered by a BEEF whose BUMP resolves to a root the header source does not hold at that height. The row is refused (ANC §16), the walk ends at M2, and M4 is an entry of the chain that no walk reaches (decision unlinked-entries).', chain: 'M', start: origin('M0'), rows: ['M0', 'M1', 'M2', 'M3-bump-altered', 'M4'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['M0', 'M1', 'M2']), tip: tipOf('M2'), deadLetters: [letter('M4', 'chain-break-timeout', 'entry-not-linked')], refused: [{ txid: T.M3.id('hex'), label: 'block-root-mismatch' }] } })
walkCase({ id: 'VA-ANC-024', description: 'Substitution: S1 consumes S0 and carries the record of M1, lifted from chain M, in an entry committed for its own action. The record declares M1\'s action, whose derivation does not match the entry (ANC §6.2).', chain: 'S', start: origin('S0'), rows: ['S0', 'S1'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['S0']), tip: tipOf('S0'), deadLetters: [letter('S1', 'integrity-fail', 'no-output-matches')] } })
walkCase({ id: 'VA-ANC-025', description: 'Wrong action identifier: W1\'s record declares an action other than the one its commitment key is derived for (ANC §6.2 steps 3-5).', chain: 'W', start: origin('W0'), rows: ['W0', 'W1'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['W0']), tip: tipOf('W0'), deadLetters: [letter('W1', 'integrity-fail', 'no-output-matches')] } })
walkCase({ id: 'VA-ANC-026', description: 'Wrong epoch: E1\'s record declares epoch 1, and its key is derived for the same action under the epoch-0 root. The reader holds both roots (ANC §3.1, §6.2 step 4).', chain: 'E', start: origin('E0'), rows: ['E0', 'E1'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['E0']), tip: tipOf('E0'), deadLetters: [letter('E1', 'integrity-fail', 'no-output-matches')] } })
walkCase({ id: 'VA-ANC-027', description: 'K1 is an action at epoch 2, committed under the epoch-2 root. A reader that holds only epochs 0 and 1 cannot derive its key (KEYS §1.10.4).', chain: 'K', start: origin('K0'), rows: ['K0', 'K1'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['K0']), tip: tipOf('K0'), deadLetters: [letter('K1', 'key-missing', 'epoch-root-not-held')] } })
walkCase({ id: 'VA-ANC-028', description: 'The chain of VA-ANC-027 for a reader that holds epochs 0, 1 and 2: K1 matches.', chain: 'K', keyring: [0, 1, 2], start: origin('K0'), rows: ['K0', 'K1'], expected: { result: 'COMPLETE', dispatched: aids(['K0', 'K1']), tip: tipOf('K1') } })
walkCase({ id: 'VA-ANC-029', description: 'D1\'s container carries bytes that do not decode as a record.', chain: 'D', start: origin('D0'), rows: ['D0', 'D1'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['D0']), tip: tipOf('D0'), deadLetters: [letter('D1', 'decode-fail', 'record-not-decodable')] } })
walkCase({ id: 'VA-ANC-030', description: 'An action that consumes no tip: N2x is committed for chain N but spends only a funding entry (ANC §4.2). The walk ends at N1, and N2x is an entry no walk reaches (decision unlinked-entries).', chain: 'N', start: origin('N0'), rows: ['N0', 'N1', 'N2x'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['N0', 'N1']), tip: tipOf('N1'), deadLetters: [letter('N2x', 'chain-break-timeout', 'entry-not-linked')] } })
walkCase({ id: 'VA-ANC-031', description: 'An action that consumes two tips: N3 spends N1\'s entry and N2x\'s entry. ANC §4.2 makes it a malformed action; ANC §7.5 names no reason for it (class `unlisted`).', chain: 'N', start: origin('N0'), rows: ['N0', 'N1', 'N2x', 'N3'], expected: { result: 'DEAD-LETTERED', dispatched: aids(['N0', 'N1']), tip: tipOf('N1'), deadLetters: [letter('N3', 'unlisted', 'two-tips-consumed')] } })

function chainTable() {
  return Object.fromEntries(Object.entries(CHAINS).map(([name, chain]) => [name, {
    accountId: ACCOUNT_ID, runtimeId: chain.runtimeId, use: chain.use,
    commitmentKeyPath: `account/${ACCOUNT_ID}/runtime/${chain.runtimeId}/action/<actionId>`
  }]))
}
function rootTable() {
  return Object.fromEntries(Object.entries(world.roots).map(([holder, epochs]) => [holder, Object.fromEntries(Object.entries(epochs).map(([ep, r]) => [ep, { root: H(r.root), derivedFrom: `SHA-512("${r.label}")` }]))]))
}
function actionTable() {
  return Object.fromEntries(Object.entries(A).map(([name, a]) => [name, { aid: a.aid, ep: a.ep }]))
}

function chainSection() {
  const headers = world.chain.headerList()
  return {
    description: 'Synthetic chain, LAB_SELF_TEST_ONLY. It is not any real network and none of its transactions is broadcast. The header list is the verifier\'s header source.',
    bits: BITS.toString(16).padStart(8, '0'),
    genesisTime: GENESIS_TIME,
    blockSpacingSeconds: BLOCK_SPACING,
    coinbaseLabel: COINBASE_LABEL,
    tipHeight: headers.length - 1,
    headersSha256: H(sha256(Buffer.concat(headers.map(h => Buffer.from(h.header, 'hex'))))),
    headers,
    payloadBlocks: world.chain.blocks.filter(b => b.height > 100).map(block => ({
      height: block.height,
      blockHashDisplay: display(block.hash),
      merkleRootDisplay: display(block.merkleRoot),
      txidsDisplay: block.txs.map(tx => tx.id('hex'))
    }))
  }
}

const keySection = () => ({
  warning: 'Public LAB_SELF_TEST_ONLY keys and roots. They control value only on the synthetic chain in this file.',
  keys: describeKeys(world.keys),
  roots: rootTable(),
  rootDerivation: `Each root is SHA-512 of its label, which starts "${ROOT_LABEL_PREFIX}". The participant holds one root per epoch; the attacker root makes the forged origin entry F.`,
  handoff: { protocolID: world.handoff.protocolID, keyID: world.handoff.keyPath, counterparty: world.handoff.counterparty, note: 'The handoff entry of M3 is locked to the recipient\'s derived key (ANC §3.4); no reader derivation under the signing namespace matches it.' }
})

const ancOracles = () => ({
  checker: {
    modules: ['src/sdx/cbor-det.mjs', 'src/sdx/tx.mjs', 'src/sdx/anc.mjs'],
    dependencies: 'Node.js builtins only (node:crypto for SHA-256, RIPEMD-160, HMAC, HKDF, secp256k1 ECDH and ECDSA verification)',
    tests: ['test/sdx-anc.test.mjs'],
    agreement: 'The generator declares each expected outcome from the case\'s construction; the checker reproduces every one, or generation stops.'
  },
  pythonChecker: {
    modules: ['test/sdx_anc.py'],
    tests: ['test/test_sdx_anc.py'],
    dependencies: 'Python standard library only (hashlib, hmac and integer arithmetic for secp256k1)',
    agreement: 'An independent implementation that reads only this file and the deployment profile, and reproduces every expected outcome.'
  },
  '@bsv/sdk': {
    version: PACKAGE.dependencies['@bsv/sdk'],
    spendValidate: `Spend.validate() accepts all ${oracle.spendsValid} inputs of the ${world.all.length} payload transactions, including the high-S input of M4.`,
    merklePath: `MerklePath.computeRoot and MerklePath.verify confirm all ${oracle.merklePaths} payload transactions against the header roots.`,
    beef: `Beef.fromBinary(...).isValid() and Beef.verify(tracker) accept the BEEF of every walk row except the altered one, and of every accepted reference (${oracle.beefValid}); Transaction.fromAtomicBEEF reads every Atomic BEEF among them (${oracle.atomicParsed}).`,
    commitmentKeys: `KeyDeriver (through ProtoWallet and PushDrop) and the checker's node:crypto derivation give the same commitment key for all ${oracle.commitmentKeys} participant entries.`
  },
  cborg: {
    version: PACKAGE.dependencies.cborg,
    encode: `cborg.encode with rfc8949EncodeOptions and src/sdx/cbor-det.mjs produce identical bytes for all ${agreement.encoded} records and references the generator encodes.`,
    decode: `cborg.decode (strict, useMaps, rejectDuplicateMapKeys) reads every accepted reference (${oracle.cborgDecoded}).`
  },
  rustParticipant: 'When TPNIL_RUST_PARTICIPANT names the binary of components/rust (bsv-blockchain/rs-sdk), components/sdx/proof/test/rust-oracle.test.mjs recomputes the merkle root of every accepted reference\'s transaction and requires agreement with the header list.'
})

// ------------------------------------------------------------------ VA-ENC

function vaEnc() {
  const index = JSON.parse(fs.readFileSync(path.join(ROOT, TEXT.suites), 'utf8'))
  const files = Object.fromEntries(index.files.map(file => [file.id, { ...file, json: JSON.parse(fs.readFileSync(path.join(ROOT, file.path), 'utf8')) }]))
  for (const file of Object.values(files)) {
    if (H(sha256(fs.readFileSync(path.join(ROOT, file.path)))) !== file.sha256) throw new Error(`${file.path}: pinned digest mismatch`)
  }
  const materialize = input => {
    switch (input.kind) {
      case 'value': return input.value
      case 'uint8array': return Uint8Array.from(input.bytes)
      case 'object': return Object.fromEntries(Object.entries(input.fields).map(([k, v]) => [k, materialize(v)]))
      case 'absent': return undefined
      case 'timestamp': return new Date(input.ms)
      case 'array': return input.items.map(materialize)
      case 'set': return new Set(input.items.map(materialize))
      default: throw new Error(`unknown input kind ${input.kind}`)
    }
  }
  const cases = []
  const cborgAgrees = []
  const cborgDiffers = []
  let n = 0
  for (const vector of files['cbor-det-v1'].json.vectors) {
    const encodedHex = H(labEncode(materialize(vector.input)))
    if (encodedHex !== vector.encoded_hex) throw new Error(`cbor-det-v1/${vector.name}: encoder output ${encodedHex}`)
    if (H(labEncode(labDecodeStrict(Buffer.from(vector.encoded_hex, 'hex')))) !== vector.encoded_hex) throw new Error(`cbor-det-v1/${vector.name}: strict round trip`)
    let viaCborg = null
    try { viaCborg = H(cborg.encode(materialize(vector.input), cborg.rfc8949EncodeOptions)) } catch { viaCborg = null }
    ;(viaCborg === vector.encoded_hex ? cborgAgrees : cborgDiffers).push(vector.name)
    cases.push({ id: `VA-ENC-${pad(++n)}`, requirement: 'SDX-A-01', origin: 'sdx-published', direction: 'encode', basis: 'required', source: { path: files['cbor-det-v1'].path, name: vector.name }, observed: { encodedHex, result: 'PASS' } })
  }
  for (const vector of files['historical-float64-decode'].json.vectors) {
    const value = labDecode(Buffer.from(vector.historical_hex, 'hex'))
    const canonicalHex = H(labEncode(value))
    if (canonicalHex !== H(labEncode(vector.decodes_to))) throw new Error(`historical-float64-decode/${vector.name}: decoded value differs`)
    cases.push({ id: `VA-ENC-${pad(++n)}`, requirement: 'SDX-A-01', origin: 'sdx-published', direction: 'decode', basis: 'required', source: { path: files['historical-float64-decode'].path, name: vector.name }, observed: { canonicalHex, result: 'PASS' } })
  }
  // Decoder cases the published suites do not cover. `basis` is `required` where ENV §3, a VEC
  // rule or CBOR well-formedness (RFC 8949 §3, Appendix F) fixes the semantic decoder's outcome,
  // and `labChoice` where the texts leave it open. Only a `required` outcome can fail an
  // implementation under test. The strict decoder's outcome is informative.
  const RFC_WF = 'RFC 8949 §3 and Appendix F (not well-formed)'
  const LAB = [
    ['c074323031332d30332d32315432303a30343a30305a', 'A tagged item (tag 0).', ['REJECT', 'tag'], ['REJECT', 'tag'], 'required', 'ENV §3 rule 4'],
    ['d818456449455446', 'Tag 24 around an embedded data item.', ['REJECT', 'tag'], ['REJECT', 'tag'], 'required', 'ENV §3 rule 4'],
    ['9f0102ff', 'An indefinite-length array.', ['REJECT', 'indefinite-length'], ['REJECT', 'indefinite-length'], 'required', 'ENV §3 rule 5'],
    ['5f42010243030405ff', 'An indefinite-length byte string.', ['REJECT', 'indefinite-length'], ['REJECT', 'indefinite-length'], 'required', 'ENV §3 rule 5'],
    ['bf616101ff', 'An indefinite-length map.', ['REJECT', 'indefinite-length'], ['REJECT', 'indefinite-length'], 'required', 'ENV §3 rule 5'],
    ['1801', 'Integer 1 with a one-byte argument head. ENV §3 lets a decoder accept it (MAY).', ['ACCEPT', '01'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (a decoder MAY accept a non-shortest head)'],
    ['1b0000000000000017', 'Integer 23 with an eight-byte argument head. ENV §3 lets a decoder accept it (MAY).', ['ACCEPT', '17'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (a decoder MAY accept a non-shortest head)'],
    ['a2616201616102', 'A map whose keys are not in bytewise order. ENV §3 states no decoder rule for it.', ['ACCEPT', 'a2616102616201'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (silent)'],
    ['a2616101616102', 'A map that carries the same key twice: well-formed, but not valid CBOR (RFC 8949 §5.6). ENV §3 states no decoder rule for it.', ['REJECT', 'duplicate-key'], ['REJECT', 'duplicate-key'], 'labChoice', 'ENV §3 (silent); RFC 8949 §5.6'],
    ['1b0020000000000000', 'Unsigned integer 2^53, outside the value domain. ENV §3 rule 3 binds the encoder; it states no decoder rule.', ['REJECT', 'integer-out-of-domain'], ['REJECT', 'integer-out-of-domain'], 'labChoice', 'ENV §3 rule 3 (encoder only)'],
    ['3b0020000000000000', 'Negative integer -(2^53) - 1, outside the value domain. ENV §3 rule 3 binds the encoder; it states no decoder rule.', ['REJECT', 'integer-out-of-domain'], ['REJECT', 'integer-out-of-domain'], 'labChoice', 'ENV §3 rule 3 (encoder only)'],
    ['fb4014000000000000', 'binary64 5.0, an integer written as a float.', ['ACCEPT', '05'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (silent); VEC historical-float64-decode covers integers above 2^32 only'],
    ['f93e00', 'binary16 1.5.', ['ACCEPT', 'fb3ff8000000000000'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (silent)'],
    ['fa3fc00000', 'binary32 1.5.', ['ACCEPT', 'fb3ff8000000000000'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (silent)'],
    ['fb8000000000000000', 'binary64 -0.0. The re-encoding as integer 0 is a laboratory interpretation: the published vectors do not pin -0 (decision cbor-det-v1-profile).', ['ACCEPT', '00'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (silent); not pinned by cbor-det-v1'],
    ['f7', 'undefined as a whole value, which ENV §3 preserves as CBOR undefined.', ['ACCEPT', 'f7'], ['ACCEPT', 'f7'], 'required', 'ENV §3 (absent-value table)'],
    ['a16161f7', 'undefined as a map member, which the encoder elides. ENV §3 states no decoder rule for it.', ['ACCEPT', 'a0'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 rule 9 (encoder only)'],
    ['81f7', 'undefined as an array element, which the encoder writes as null. ENV §3 states no decoder rule for it.', ['ACCEPT', '81f6'], ['REJECT', 'non-deterministic'], 'labChoice', 'ENV §3 (absent-value table, encoder only)'],
    ['62c328', 'A text string that is not valid UTF-8: well-formed, but not valid CBOR (RFC 8949 §5.3.1). ENV §3 states no decoder rule for it.', ['REJECT', 'invalid-utf8'], ['REJECT', 'invalid-utf8'], 'labChoice', 'ENV §3 (silent); RFC 8949 §5.3.1'],
    ['0000', 'Two top-level items where one data item is expected.', ['REJECT', 'trailing-bytes'], ['REJECT', 'trailing-bytes'], 'required', `${RFC_WF}: too much data`],
    ['f818', 'A two-byte simple value below 32.', ['REJECT', 'not-well-formed'], ['REJECT', 'not-well-formed'], 'required', `${RFC_WF}; RFC 8949 §3.3`],
    ['f820', 'Simple value 32: well-formed and unassigned. Refusing it is a laboratory choice.', ['REJECT', 'simple-value'], ['REJECT', 'simple-value'], 'labChoice', 'ENV §3 (silent); RFC 8949 §3.3'],
    ['e0', 'Simple value 0: well-formed and unassigned. Refusing it is a laboratory choice.', ['REJECT', 'simple-value'], ['REJECT', 'simple-value'], 'labChoice', 'ENV §3 (silent); RFC 8949 §3.3'],
    ['1c', 'Reserved additional information 28.', ['REJECT', 'not-well-formed'], ['REJECT', 'not-well-formed'], 'required', RFC_WF],
    ['ff', 'A break outside an indefinite-length item.', ['REJECT', 'not-well-formed'], ['REJECT', 'not-well-formed'], 'required', RFC_WF],
    ['5a0000000501', 'A byte string whose declared length exceeds the input.', ['REJECT', 'truncated'], ['REJECT', 'truncated'], 'required', `${RFC_WF}: not enough data`]
  ]
  const run = (fn, bytes) => { try { return ['ACCEPT', H(labEncode(fn(bytes)))] } catch (error) { return ['REJECT', error.code] } }
  const shape = ([result, value]) => (result === 'ACCEPT' ? { result, canonicalHex: value } : { result, reason: value })
  let lab = 100
  for (const [hex, description, semantic, strict, basis, clause] of LAB) {
    const bytes = Buffer.from(hex, 'hex')
    const gotSemantic = run(labDecode, bytes)
    const gotStrict = run(labDecodeStrict, bytes)
    if (JSON.stringify(gotSemantic) !== JSON.stringify(semantic) || JSON.stringify(gotStrict) !== JSON.stringify(strict)) throw new Error(`${hex}: decoder gave ${gotSemantic} / ${gotStrict}`)
    cases.push({ id: `VA-ENC-${pad(++lab)}`, requirement: 'SDX-A-01', origin: 'lab-derived', direction: 'decode', basis, source: { path: TEXT.env, clause }, description, input: { hex }, expected: shape(semantic), informative: { strict: shape(strict) } })
  }
  // Encoder rules of ENV §3 the published suites do not cover. The expected bytes are built
  // from the rule with cborg, independently of the laboratory encoder, which must agree.
  const viaCborg = value => H(cborg.encode(value, cborg.rfc8949EncodeOptions))
  const ENCODE = [
    [{ kind: 'timestamp', ms: 1786461096765 }, 'A timestamp: integer milliseconds since the Unix epoch, untagged.', viaCborg(1786461096765), 'ENV §3 rule 7'],
    [{ kind: 'object', fields: { a: { kind: 'absent' }, b: { kind: 'value', value: null } } }, 'A map with an absent member and a null member: the absent one is elided and the null one kept.', viaCborg({ b: null }), 'ENV §3 rule 9'],
    [{ kind: 'array', items: [{ kind: 'absent' }, { kind: 'value', value: null }] }, 'An array whose first element is absent: it is written as null.', viaCborg([null, null]), 'ENV §3 (absent-value table)'],
    [{ kind: 'absent' }, 'An absent whole value: CBOR undefined.', 'f7', 'ENV §3 (absent-value table)'],
    [{ kind: 'set', items: [{ kind: 'value', value: 'b' }, { kind: 'value', value: 1 }, { kind: 'value', value: 'a' }] }, 'A set of three members: an array sorted by the members\' encodings.', `83${['b', 1, 'a'].map(viaCborg).sort().join('')}`, 'ENV §3 rule 6']
  ]
  let labEncodeId = 200
  for (const [input, description, expectedHex, clause] of ENCODE) {
    const got = H(labEncode(materialize(input)))
    if (got !== expectedHex) throw new Error(`${description}: encoder gave ${got}, rule gives ${expectedHex}`)
    cases.push({ id: `VA-ENC-${pad(++labEncodeId)}`, requirement: 'SDX-A-01', origin: 'lab-derived', direction: 'encode', basis: 'required', source: { path: TEXT.env, clause }, description, input, expected: { encodedHex: expectedHex } })
  }
  return {
    schema: 'tpnil-sdx-vectors@0.1.0',
    suite: 'VA-ENC',
    claim: 'LAB_SELF_TEST_ONLY',
    status: 'BASELINE-v0.1',
    requirements: ['SDX-A-01'],
    citations: [
      { path: TEXT.env, clause: 'ENV §3' },
      { path: TEXT.env, clause: 'ENV §17.6' },
      { path: TEXT.base, clause: 'BASE §3.1, §6' },
      { path: TEXT.vec, clause: 'VEC' },
      { path: TEXT.suites, clause: 'cbor-det-v1, historical-float64-decode' }
    ],
    references: references(['RFC 8949']),
    outcomeTags: {
      required: 'The outcome follows from an ENV §3 MUST, a VEC rule, or CBOR well-formedness (RFC 8949 §3 and Appendix F), which ENV §3 presupposes. An implementation under test that differs FAILS the case.',
      labChoice: 'The texts leave the outcome open. The case records the laboratory decoder\'s choice; an implementation under test that differs is reported, and never FAILS on it.',
      informative: 'The strict decoder\'s outcome is a laboratory choice beyond ENV §3 (decision cbor-det-v1-decoder). It is recorded for the suites that read maps strictly and is never an expectation under SDX-A-01.'
    },
    decisions: [
      { id: 'cbor-det-v1-profile', kind: BASIS, text: 'The encoder follows the published `cbor-det-v1` vectors where they and the ENV §3 prose differ, as VEC directs: safe integers (±(2^53 - 1)) take the shortest integer head; every other number, including integral values beyond the safe range, is binary64 (vectors `int-above-safe-range-stays-float64`, `int-far-above-safe-range-stays-float64`); bigint inputs are refused. Map keys are ordered by their encoded bytes; absent map members are elided, absent array elements become null, and an absent whole value is CBOR undefined (ENV §3).' },
      { id: 'cbor-det-v1-specials', kind: READING, text: 'The encoder writes -0 as integer 0, NaN as fb7ff8000000000000 and ±Infinity as binary64. The published vectors do not pin these values, and the laboratory cross-checked them against cbor-x 1.6.9, where the published suite names cbor-x 1.6.4 (coverage gap ENV-3).' },
      { id: 'cbor-det-v1-decoder', kind: BASIS, text: 'The semantic decoder implements ENV §3: it rejects tags and indefinite-length items, accepts non-shortest heads, and returns binary64 values as numbers, so the historical-float64-decode bytes read back to the integers shown. It rejects input that is not well-formed CBOR (RFC 8949 §3, Appendix F). As laboratory choices it also rejects well-formed input outside the profile: integers beyond ±(2^53 - 1), maps with duplicate keys and text that is not valid UTF-8 (both not valid, RFC 8949 §5.3.1, §5.6), and unassigned simple values. The strict decoder additionally requires the input to be the deterministic encoding of the decoded value.' },
      { id: 'lab-bounds', kind: CHOICE, text: 'The checker bounds nesting depth at 64 and input at 16 MiB, refuses duplicate set members and text containing a lone surrogate on encode. ENV §17.6 requires bounds and fixes no values, so these are laboratory bounds. A refusal caused by one of them when reading an implementation\'s output is reported as ERROR, never FAIL.' },
      { id: 'thin-suite', kind: CHOICE, text: 'Cases VA-ENC-001 to 044 reference the published SDX vectors by file and name and record this implementation\'s output; the expected bytes and values are those of the published files, which are stored unchanged and pinned by SHA-256. Cases VA-ENC-101 to 126 are laboratory-derived decoder cases, and VA-ENC-201 onward laboratory-derived encoder cases; each carries its `basis` tag and the clause it rests on.' }
    ],
    implementation: { encoder: 'src/sdx/cbor-det.mjs encode()', semanticDecoder: 'src/sdx/cbor-det.mjs decode()', strictDecoder: 'src/sdx/cbor-det.mjs decodeStrict()', dependencies: 'none' },
    imports: index.files.map(file => ({ id: file.id, path: file.path, sha256: file.sha256, vectors: file.vectors, direction: file.direction, passed: file.vectors })),
    oracles: {
      sdxPublished: 'For cases VA-ENC-001 to 044 the SDX published suites are the oracle: the expected bytes come from SDX, not from this implementation. Both suites pass in full.',
      labDerived: 'For the laboratory-derived cases the generator declares each expected outcome from the rule it cites and the checker must reproduce it. The encoder cases build their expected bytes with cborg. test/test_sdx_anc.py replays every laboratory-derived case with a separate Python standard-library decoder and encoder.',
      cborg: { version: PACKAGE.dependencies.cborg, options: 'rfc8949EncodeOptions', agrees: cborgAgrees.length, differs: cborgDiffers, note: 'cborg follows RFC 8949 preferred serialization: it writes 2^53 as an integer and each non-integer as the shortest float that preserves it. The SDX profile writes both as binary64, so the published vectors, not RFC 8949 §4.2.1 alone, define its float rule.' }
    },
    generator: GENERATOR,
    cases
  }
}

// ------------------------------------------------------------------ assemble

const documents = {
  'fixtures/sdx/v1/va-enc/vectors.json': vaEnc(),
  'fixtures/sdx/v1/va-anc/vectors.json': {
    schema: 'tpnil-sdx-vectors@0.1.0',
    suite: 'VA-ANC',
    claim: 'LAB_SELF_TEST_ONLY',
    status: 'BASELINE-v0.1',
    requirements: ['SDX-A-07'],
    profile: { id: PROFILE.profile, path: PROFILE_PATH, sha256: H(createHash('sha256').update(PROFILE_BYTES).digest()) },
    citations: [
      { path: TEXT.anc, clause: 'ANC §2.1, §2.2, §2.3' },
      { path: TEXT.anc, clause: 'ANC §3.1, §3.3, §3.4' },
      { path: TEXT.anc, clause: 'ANC §4.1, §4.2' },
      { path: TEXT.anc, clause: 'ANC §6.1, §6.2' },
      { path: TEXT.anc, clause: 'ANC §7.1, §7.2, §7.5' },
      { path: TEXT.anc, clause: 'ANC §12.6, §16' },
      { path: TEXT.keys, clause: 'KEYS §1.4.2, §1.6.1, §1.8.1, §1.8.2, §1.8.3, §1.10.4, §1.10.5' },
      { path: TEXT.env, clause: 'ENV §6.1' },
      { path: TEXT.base, clause: 'BASE §3.4' }
    ],
    references: references(['BRC-62', 'BRC-74', 'BRC-95', 'BRC-42', 'RFC 5869']),
    decisions: Object.values(DECISIONS),
    outcomeClasses: DEAD_LETTER_CLASSES,
    testKeys: keySection(),
    chain: chainSection(),
    chains: chainTable(),
    actions: actionTable(),
    standIn: { proto: STAND_IN_PROTO, body: STAND_IN_BODY },
    transactions: rowTable,
    generator: GENERATOR,
    oracles: null,
    cases
  }
}
documents['fixtures/sdx/v1/va-anc/vectors.json'].oracles = ancOracles()
for (const document of Object.values(documents)) assertStrictJson(document)

const mode = process.argv[2]
let stale = 0
for (const [file, document] of Object.entries(documents)) {
  const text = `${JSON.stringify(document, null, 2)}\n`
  const target = path.join(ROOT, file)
  if (mode === '--write') {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, text)
    console.log(`wrote ${file} (${document.cases.length} cases, ${text.length} bytes)`)
  } else if (mode === '--check') {
    const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null
    if (current !== text) { stale++; console.error(`stale: ${file}`) } else console.log(`current: ${file} (${document.cases.length} cases)`)
  } else {
    console.log(`${file}: ${document.cases.length} cases`)
  }
}
if (stale) process.exit(1)
