// Synthetic block chain for laboratory vectors. Blocks hold a synthetic coinbase and the
// payload transactions; headers are complete 80-byte headers with regtest-difficulty proof
// of work found by nonce search. Nothing here is broadcast or touches any network.

import { createHash } from 'node:crypto'
import { MerklePath, P2PKH, Transaction, UnlockingScript } from '@bsv/sdk'

export const BITS = 0x207fffff
export const GENESIS_TIME = 1767225600 // 2026-01-01T00:00:00Z, synthetic
export const BLOCK_SPACING = 600
export const COINBASE_LABEL = 'TPNIL LAB_SELF_TEST_ONLY synthetic coinbase; never broadcast'

const sha256d = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest()
const display = bytes => Buffer.from(bytes).reverse().toString('hex')

function target(bits) {
  return BigInt(bits & 0x007fffff) << BigInt(8 * ((bits >>> 24) - 3))
}

// Bitcoin merkle levels (SHA-256d, last node paired with itself), internal byte order.
export function merkleLevels(txids) {
  const levels = [txids.map(id => Buffer.from(id))]
  while (levels.at(-1).length > 1) {
    const level = levels.at(-1)
    const next = []
    for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]])))
    levels.push(next)
  }
  return levels
}

function pathFor(levels, index) {
  if (levels.length === 1) return [[{ offset: 0, hash: display(levels[0][0]), txid: true }]]
  const path = []
  for (let h = 0; h < levels.length - 1; h++) {
    const position = Math.floor(index / 2 ** h)
    const siblingOffset = position % 2 === 0 ? position + 1 : position - 1
    const sibling = siblingOffset < levels[h].length ? { offset: siblingOffset, hash: display(levels[h][siblingOffset]) } : { offset: siblingOffset, duplicate: true }
    const leaves = h === 0 ? [{ offset: position, hash: display(levels[0][position]), txid: true }, sibling] : [sibling]
    path.push(leaves.sort((a, b) => a.offset - b.offset))
  }
  return path
}

export class SyntheticChain {
  constructor(coinbaseKey) {
    this.coinbaseScript = new P2PKH().lock(coinbaseKey.publicKey.toHash())
    this.blocks = []
    this.located = new Map()
  }

  coinbase(height) {
    const label = Buffer.alloc(4)
    label.writeUInt32LE(height)
    return new Transaction(1, [{
      sourceTXID: '00'.repeat(32), sourceOutputIndex: 0xffffffff, sequence: 0xffffffff,
      unlockingScript: new UnlockingScript().writeBin([...label]).writeBin([...Buffer.from(COINBASE_LABEL)])
    }], [{ lockingScript: this.coinbaseScript, satoshis: 5_000_000_000 }], 0)
  }

  mine(payload = []) {
    const height = this.blocks.length
    const txs = [this.coinbase(height), ...payload]
    const ids = txs.map(tx => Buffer.from(tx.hash()))
    const levels = merkleLevels(ids)
    const merkleRoot = levels.at(-1)[0]
    const header = Buffer.alloc(80)
    header.writeUInt32LE(0x20000000, 0)
    ;(height === 0 ? Buffer.alloc(32) : this.blocks.at(-1).hash).copy(header, 4)
    merkleRoot.copy(header, 36)
    header.writeUInt32LE(GENESIS_TIME + height * BLOCK_SPACING, 68)
    header.writeUInt32LE(BITS, 72)
    let nonce = 0
    for (;; nonce++) {
      header.writeUInt32LE(nonce, 76)
      if (BigInt(`0x${display(sha256d(header))}`) <= target(BITS)) break
    }
    const block = { height, txs, ids, merkleRoot, header: Buffer.from(header), hash: sha256d(header), paths: new Map() }
    txs.forEach((tx, index) => {
      const merklePath = new MerklePath(height, pathFor(levels, index))
      if (merklePath.computeRoot(tx.id('hex')) !== display(merkleRoot)) throw new Error('synthetic merkle path disagrees with @bsv/sdk')
      block.paths.set(ids[index].toString('hex'), merklePath)
      this.located.set(ids[index].toString('hex'), { height, index })
    })
    this.blocks.push(block)
    return block
  }

  pathOf(tx) {
    const key = Buffer.from(tx.hash()).toString('hex')
    const where = this.located.get(key)
    if (!where) return null
    return this.blocks[where.height].paths.get(key)
  }

  headerList() {
    return this.blocks.map(block => ({ height: block.height, header: block.header.toString('hex') }))
  }

  sdkTracker() {
    const roots = new Map(this.blocks.map(block => [block.height, display(block.merkleRoot)]))
    return { isValidRootForHeight: async (root, height) => roots.get(height) === root, currentHeight: async () => this.blocks.length - 1 }
  }
}

export { display, sha256d }
