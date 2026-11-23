// Builds the synthetic laboratory world for VA-ANC: one synthetic block chain and the anchored
// chains of one participant (ANC §2-§4), each action committed under the real ANC §3.1
// commitment key of the laboratory deployment profile, plus the entries the negative cases
// need. Every transaction is signed with @bsv/sdk and is valid; none is broadcast.

import { BigNumber, LockingScript, OP, P2PKH, PrivateKey, ProtoWallet, PushDrop, Transaction, UnlockingScript } from '@bsv/sdk'
import { labKeys, labRoots, secp256k1SeedOf } from './keys.mjs'
import { SyntheticChain } from './chain.mjs'
import { det } from './cbor.mjs'
import { createHash } from 'node:crypto'

const utf8 = text => Buffer.from(text, 'utf8')
export const txid = tx => Buffer.from(tx.hash())

export const STAND_IN_PROTO = 'tpnil-sdx-lab-stand-in@0.1.0'
export const STAND_IN_BODY = 'LAB_SELF_TEST_ONLY stand-in for an SDX v0.1 record: it carries hdr.aid and hdr.ep in clear and is not a record envelope'
export const ACCOUNT_ID = '3MNQpxFAsp' // KEYS §1.8.1 worked example

// One runtime per chain. M uses the KEYS §1.8.1 worked-example runtime; the others are
// laboratory values of the same shape.
export const CHAINS = Object.freeze({
  M: { runtimeId: '8kRt2wVbZq', use: 'The main chain: five actions from the origin' },
  S: { runtimeId: 'Sb2Mx7QkTd', use: 'Substitution: a record lifted from chain M into an entry committed for this chain' },
  W: { runtimeId: 'Wa4Nc8RpLe', use: 'Wrong action identifier' },
  E: { runtimeId: 'Ep6Hd9SqMf', use: 'Wrong epoch' },
  K: { runtimeId: 'Km3Je5TrNg', use: 'An action at epoch 2' },
  D: { runtimeId: 'Dc7Kf2UsPh', use: 'A record that does not decode' },
  N: { runtimeId: 'Nt8Lg3VtQj', use: 'An action that consumes no tip, and one that consumes two' }
})

// ULID (KEYS §1.6.2): 48-bit milliseconds then 80 bits, in Crockford base32. The random part
// is the first 80 bits of SHA-256 of a label, so identifiers are fixed.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export function ulid(ms, label) {
  let time = ''
  for (let n = BigInt(ms), i = 0; i < 10; i++, n >>= 5n) time = CROCKFORD[Number(n & 31n)] + time
  let random = ''
  for (let n = BigInt(`0x${createHash('sha256').update(`TPNIL VA-ANC action ${label}`).digest('hex').slice(0, 20)}`), i = 0; i < 16; i++, n >>= 5n) random = CROCKFORD[Number(n & 31n)] + random
  return time + random
}

export function standIn(aid, ep) {
  return det({ proto: STAND_IN_PROTO, hdr: { aid, ep }, body: STAND_IN_BODY })
}

const p2pkhLock = key => new P2PKH().lock(key.publicKey.toHash())
const p2pkhUnlock = key => new P2PKH().unlock(key.privateKey)

async function build(inputs, outputs, version = 1) {
  const tx = new Transaction(version, [], [], 0)
  for (const input of inputs) tx.addInput({ sourceTransaction: input.tx, sourceOutputIndex: input.vout, unlockingScriptTemplate: input.unlock, sequence: 0xffffffff })
  for (const output of outputs) tx.addOutput({ lockingScript: output.script, satoshis: output.satoshis })
  await tx.sign()
  return tx
}

const SECP256K1_N = new BigNumber('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

// Replaces the DER signature of a one-push unlocking script with its high-S twin (r, n - s).
// BIP 143 signatures do not cover unlocking scripts, so the signature stays valid.
function highS(unlocking) {
  const chunk = unlocking.chunks[0]
  const sig = Buffer.from(chunk.data)
  const lenR = sig[3]
  const r = sig.subarray(4, 4 + lenR)
  const s = new BigNumber([...sig.subarray(6 + lenR, sig.length - 1)])
  const high = SECP256K1_N.sub(s).toArray('be')
  const sBytes = high[0] & 0x80 ? [0, ...high] : high
  const body = Buffer.concat([Buffer.from([0x02, r.length]), r, Buffer.from([0x02, sBytes.length]), Buffer.from(sBytes)])
  const der = Buffer.concat([Buffer.from([0x30, body.length]), body, sig.subarray(sig.length - 1)])
  return new UnlockingScript().writeBin([...der])
}

export async function buildWorld(profile) {
  const keys = labKeys()
  const roots = labRoots()
  const label = profile.derivation.curveLabels.secp256k1
  const words = profile.derivation.keyPath.keywords
  const signing = profile.recordKeyIdentifiers.commitment.protocolID
  const handoff = [2, profile.derivation.namespaces.handoff]
  const walletOf = root => new ProtoWallet(PrivateKey.fromHex(secp256k1SeedOf(root, label).toString('hex')))
  const wallets = {
    participant: Object.fromEntries(Object.entries(roots.participant).map(([ep, r]) => [ep, walletOf(r.root)])),
    attacker: Object.fromEntries(Object.entries(roots.attacker).map(([ep, r]) => [ep, walletOf(r.root)]))
  }
  const keyPath = (runtime, aid) => `${words.level1}/${ACCOUNT_ID}/${words.level2}/${CHAINS[runtime].runtimeId}/${words.level3}/${aid}`
  const commitments = []
  // `<record> DROP <commitment key> CHECKSIG` under the ANC §3.1 derivation, by @bsv/sdk PushDrop.
  const containerLock = async ({ runtime, aid, ep = 0, record, holder = 'participant' }) => {
    const wallet = wallets[holder][ep]
    const script = await new PushDrop(wallet).lock([[...record]], signing, keyPath(runtime, aid), 'self', true, false, 'after')
    const { publicKey } = await wallet.getPublicKey({ protocolID: signing, keyID: keyPath(runtime, aid), counterparty: 'self', forSelf: true })
    commitments.push({ runtime, aid, ep, holder, publicKey })
    return script
  }
  const containerUnlock = ({ runtime, aid, ep = 0 }) => new PushDrop(wallets.participant[ep]).unlock(signing, keyPath(runtime, aid), 'self', 'all', false)

  const chain = new SyntheticChain(keys.coinbase)
  const all = []
  const track = tx => { all.push(tx); return tx }

  // Heights 0-100: genesis and coinbase-only blocks, so that the genesis coinbase is mature.
  const genesis = chain.mine([])
  for (let i = 0; i < 100; i++) chain.mine([])

  // Height 101: master distribution. Height 102: one funding output per transaction.
  const master = track(await build([{ tx: genesis.txs[0], vout: 0, unlock: p2pkhUnlock(keys.coinbase) }], [
    { script: p2pkhLock(keys.funding), satoshis: 1_000_000 },
    { script: p2pkhLock(keys.coinbase), satoshis: 5_000_000_000 - 1_000_000 - 1_000 }
  ]))
  chain.mine([master])
  const FUNDING_OUTPUTS = 32
  const funding = track(await build([{ tx: master, vout: 0, unlock: p2pkhUnlock(keys.funding) }], [
    ...Array.from({ length: FUNDING_OUTPUTS }, () => ({ script: p2pkhLock(keys.funding), satoshis: 10_000 })),
    { script: p2pkhLock(keys.funding), satoshis: 1_000_000 - FUNDING_OUTPUTS * 10_000 - 1_000 }
  ]))
  chain.mine([funding])
  let nextFunding = 0
  const fee = () => ({ tx: funding, vout: nextFunding++, unlock: p2pkhUnlock(keys.funding) })
  const change = () => ({ script: p2pkhLock(keys.funding), satoshis: 9_000 })

  // Actions. Times are fixed synthetic milliseconds, one second apart.
  const T0 = 1767225600000
  let tick = 0
  const actions = {}
  const action = (name, ep = 0, aid = null) => {
    const value = { name, aid: aid ?? ulid(T0 + 1000 * tick++, name), ep }
    actions[name] = value
    return value
  }
  // M0 carries the KEYS §1.8.1 worked-example action identifier.
  const m = [action('M0', 0, '01JB8ZK3QN7T4YVX2C9M5RDPWA'), action('M1'), action('M2'), action('M3'), action('M4')]
  const m3h = action('M3-handoff')
  const records = {}
  const recordOf = a => (records[a.name] ??= standIn(a.aid, a.ep))
  const entry = async (runtime, a, o = {}) => ({ script: await containerLock({ runtime, aid: a.aid, ep: a.ep, record: o.record ?? recordOf(a), ...o }), satoshis: profile.anchoring.minimumEntryValue })
  const origin = async (runtime, a) => track(await build([fee()], [await entry(runtime, a), change()]))
  const consume = (runtime, a, tx, vout) => ({ tx, vout, unlock: containerUnlock({ runtime, aid: a.aid, ep: a.ep }) })

  // Height 103: the origin of every chain, the forged origin entry and two mis-shaped containers.
  const M0 = await origin('M', m[0])
  const s0 = action('S0'); const w0 = action('W0'); const e0 = action('E0'); const k0 = action('K0'); const d0 = action('D0'); const n0 = action('N0')
  const S0 = await origin('S', s0); const W0 = await origin('W', w0); const E0 = await origin('E', e0)
  const K0 = await origin('K', k0); const D0 = await origin('D', d0); const N0 = await origin('N', n0)
  // The forged origin: the participant's origin record, committed by the attacker's root under
  // chain M's key path. It is a well-formed container that no participant derivation matches.
  const F = track(await build([fee()], [await entry('M', m[0], { holder: 'attacker' }), change()]))
  // Mis-shaped containers for the reference cases: a non-minimal push (OP_PUSHDATA1 for a short
  // record, assembled by hand on purpose) and a container with two data fields.
  const nmAction = action('NM')
  const nmRecord = det({ synthetic: true, note: 'LAB_SELF_TEST_ONLY short record' })
  if (nmRecord.length > 75) throw new Error('the non-minimal push fixture needs a record of at most 75 bytes')
  const nmKey = Buffer.from((await wallets.participant[0].getPublicKey({ protocolID: signing, keyID: keyPath('M', nmAction.aid), counterparty: 'self', forSelf: true })).publicKey, 'hex')
  const NM = track(await build([fee()], [{ script: LockingScript.fromBinary([OP.OP_PUSHDATA1, nmRecord.length, ...nmRecord, OP.OP_DROP, 33, ...nmKey, OP.OP_CHECKSIG]), satoshis: 1 }, change()]))
  const tfAction = action('TF')
  const tfScript = await new PushDrop(wallets.participant[0]).lock([[...recordOf(tfAction)], [...utf8('second data field')]], signing, keyPath('M', tfAction.aid), 'self', true, false, 'after')
  const TF = track(await build([fee()], [{ script: tfScript, satoshis: 1 }, change()]))
  chain.mine([M0, S0, W0, E0, K0, D0, N0, F, NM, TF])

  // Height 104: the second action of every chain, including the negative ones.
  const M1 = track(await build([fee(), consume('M', m[0], M0, 0)], [await entry('M', m[1]), change()]))
  const s1 = action('S1')
  // S1 carries the record of M1 (aid of M1) in an entry committed for its own action S1.
  const S1 = track(await build([fee(), consume('S', s0, S0, 0)], [await entry('S', s1, { record: recordOf(m[1]) }), change()]))
  const w1 = action('W1'); const w1x = action('W1-declared')
  // W1's record declares another action identifier than the one its key is derived for.
  const W1 = track(await build([fee(), consume('W', w0, W0, 0)], [await entry('W', w1, { record: recordOf(w1x) }), change()]))
  // E1's record declares epoch 1; its key is derived for the same action under the epoch-0 root.
  const e1 = action('E1')
  records['E1-declared'] = standIn(e1.aid, 1)
  const E1 = track(await build([fee(), consume('E', e0, E0, 0)], [await entry('E', e1, { record: records['E1-declared'] }), change()]))
  // K1 is an action at epoch 2, correctly committed under the epoch-2 root.
  const k1 = action('K1', 2)
  const K1 = track(await build([fee(), consume('K', k0, K0, 0)], [await entry('K', k1), change()]))
  // D1's container carries bytes that do not decode as a record.
  const d1 = action('D1')
  const D1_RECORD = Buffer.concat([Buffer.from([0xff]), utf8('LAB_SELF_TEST_ONLY bytes that do not decode as a record')])
  const D1 = track(await build([fee(), consume('D', d0, D0, 0)], [await entry('D', d1, { record: D1_RECORD }), change()]))
  const n1 = action('N1')
  const N1 = track(await build([fee(), consume('N', n0, N0, 0)], [await entry('N', n1), change()]))
  chain.mine([M1, S1, W1, E1, K1, D1, N1])

  // Height 105: M2 and M3 in one block, ordered by spend (ANC §7.2). M2's entry is output 1; M3
  // consumes it with input 0 and carries a handoff entry before its own (ANC §2.3, §3.4).
  // N2x is an action of chain N that consumes no tip (ANC §4.2).
  const M2 = track(await build([fee(), consume('M', m[1], M1, 0)], [change(), await entry('M', m[2])]))
  const recipient = keys.handoffRecipient.publicKey.toString()
  const handoffKeyPath = `${keyPath('M', m[3].aid)}/handoff/${createHash('sha256').update('TPNIL VA-ANC handoff').digest('hex').slice(0, 32)}`
  const handoffScript = await new PushDrop(wallets.participant[0]).lock([[...recordOf(m3h)]], handoff, handoffKeyPath, recipient, false, false, 'after')
  const M3 = track(await build([consume('M', m[2], M2, 1), fee()], [{ script: handoffScript, satoshis: 1 }, await entry('M', m[3]), change()]))
  const n2x = action('N2x')
  const N2x = track(await build([fee()], [await entry('N', n2x), change()]))
  chain.mine([M2, M3, N2x])

  // Height 106: M4, a version-2 transaction whose consuming input carries a high-S signature
  // (KEYS §1.8.3), and N3, which consumes both tips of chain N.
  const M4 = await build([fee(), consume('M', m[3], M3, 1)], [await entry('M', m[4]), change()], 2)
  M4.inputs[1].unlockingScript = highS(M4.inputs[1].unlockingScript)
  track(M4)
  const n3 = action('N3')
  const N3 = track(await build([fee(), consume('N', n1, N1, 0), consume('N', n2x, N2x, 0)], [await entry('N', n3), change()]))
  chain.mine([M4, N3])

  return {
    keys, roots, chain, all, master, funding, actions, records, commitments,
    transactions: { M0, M1, M2, M3, M4, S0, S1, W0, W1, E0, E1, K0, K1, D0, D1, N0, N1, N2x, N3, F, NM, TF },
    containers: { M0: 0, M1: 0, M2: 1, M3: 1, M4: 0, S0: 0, S1: 0, W0: 0, W1: 0, E0: 0, E1: 0, K0: 0, K1: 0, D0: 0, D1: 0, N0: 0, N1: 0, N2x: 0, N3: 0, F: 0, NM: 0, TF: 0 },
    handoff: { keyPath: handoffKeyPath, protocolID: handoff, counterparty: recipient, record: recordOf(m3h), aid: m3h.aid },
    nm: { record: nmRecord }, tf: { record: recordOf(tfAction), aid: tfAction.aid },
    d1Record: D1_RECORD
  }
}
