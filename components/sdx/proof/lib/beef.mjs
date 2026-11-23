// BEEF V1 (BRC-62) and Atomic BEEF (BRC-95) writer used by the generator. It writes exactly
// the transactions and BUMPs a case names, in the order given, so that malformed cases can
// be expressed; well-formed outputs are re-read with @bsv/sdk as an oracle.

const varint = n => {
  if (n < 0xfd) return Buffer.from([n])
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b }
  const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b
}

// entries: [{ raw: Uint8Array, bump: Uint8Array | null }]
export function beefV1(entries) {
  const bumps = []
  const indexOf = bump => {
    const key = Buffer.from(bump).toString('hex')
    let index = bumps.findIndex(existing => existing === key)
    if (index < 0) { bumps.push(key); index = bumps.length - 1 }
    return index
  }
  const txParts = []
  for (const entry of entries) {
    txParts.push(Buffer.from(entry.raw))
    if (entry.bump) txParts.push(Buffer.from([1]), varint(indexOf(entry.bump)))
    else txParts.push(Buffer.from([0]))
  }
  return Buffer.concat([
    Buffer.from('0100beef', 'hex'), varint(bumps.length), ...bumps.map(b => Buffer.from(b, 'hex')),
    varint(entries.length), ...txParts
  ])
}

export function atomicBeef(subjectTxid, beef) {
  return Buffer.concat([Buffer.from('01010101', 'hex'), Buffer.from(subjectTxid), Buffer.from(beef)])
}
