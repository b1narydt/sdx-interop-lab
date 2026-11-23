import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { CborDetError, decode, decodeStrict, encode, isDeterministic } from '../src/sdx/cbor-det.mjs'

const read = path => fs.readFileSync(new URL(`../${path}`, import.meta.url))
const json = path => JSON.parse(read(path))
const hex = bytes => Buffer.from(bytes).toString('hex')
const INDEX = json('fixtures/sdx/v1/standards/cbor-det-v1/index.json')
const SUITE = json('fixtures/sdx/v1/va-enc/vectors.json')
const file = id => INDEX.files.find(f => f.id === id)
const published = id => json(file(id).path)
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
const code = fn => { try { fn(); return null } catch (error) { assert.ok(error instanceof CborDetError, `unexpected ${error}`); return error.code } }

test('LAB_SELF_TEST_ONLY: the SDX cbor-det-v1 suites are stored unchanged and pinned', () => {
  assert.equal(INDEX.files.length, 2)
  for (const entry of INDEX.files) {
    const bytes = read(entry.path)
    assert.equal(bytes.length, entry.bytes, entry.path)
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256, entry.path)
    assert.equal(json(entry.path).vectors.length, entry.vectors)
    assert.match(entry.sourceUrl, /^https:\/\/sdxprotocol\.org\/vectors\//)
  }
  assert.equal(INDEX.licence.reference, 'LICENSES/SDX-Specification-License-1.0.reference.txt')
})

test('LAB_SELF_TEST_ONLY: the encoder reproduces every published cbor-det-v1 vector byte for byte', () => {
  const suite = published('cbor-det-v1')
  assert.equal(suite.vectors.length, 36)
  for (const vector of suite.vectors) {
    assert.equal(hex(encode(materialize(vector.input))), vector.encoded_hex, vector.name)
    // Each published encoding is deterministic and survives the strict decoder.
    assert.equal(hex(encode(decodeStrict(Buffer.from(vector.encoded_hex, 'hex')))), vector.encoded_hex, vector.name)
  }
})

test('LAB_SELF_TEST_ONLY: the semantic decoder reads every historical-float64-decode vector to its integer; the strict decoder refuses them', () => {
  const suite = published('historical-float64-decode')
  assert.equal(suite.vectors.length, 8)
  const plain = value => value instanceof Map ? Object.fromEntries([...value].map(([k, v]) => [k, plain(v)])) : value
  for (const vector of suite.vectors) {
    const bytes = Buffer.from(vector.historical_hex, 'hex')
    assert.deepEqual(plain(decode(bytes)), vector.decodes_to, vector.name)
    assert.equal(code(() => decodeStrict(bytes)), 'non-deterministic', vector.name)
  }
})

test('LAB_SELF_TEST_ONLY: VA-ENC records match a fresh run of the encoder and decoders', () => {
  assert.equal(SUITE.schema, 'tpnil-sdx-vectors@0.1.0')
  assert.equal(SUITE.suite, 'VA-ENC')
  assert.equal(SUITE.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(SUITE.status, 'BASELINE-v0.1')
  assert.deepEqual(SUITE.requirements, ['SDX-A-01'])
  for (const citation of SUITE.citations) assert.ok(fs.existsSync(new URL(`../${citation.path}`, import.meta.url)), citation.path)
  const byName = id => new Map(published(id).vectors.map(v => [v.name, v]))
  const encodeVectors = byName('cbor-det-v1')
  const decodeVectors = byName('historical-float64-decode')
  let publishedCases = 0
  let labCases = 0
  const tags = { required: 0, labChoice: 0 }
  for (const item of SUITE.cases) {
    assert.equal(item.requirement, 'SDX-A-01')
    assert.ok(['required', 'labChoice'].includes(item.basis), item.id)
    tags[item.basis]++
    if (item.origin === 'sdx-published') {
      publishedCases++
      if (item.direction === 'encode') {
        const vector = encodeVectors.get(item.source.name)
        assert.equal(item.observed.encodedHex, vector.encoded_hex, item.id)
        assert.equal(hex(encode(materialize(vector.input))), item.observed.encodedHex, item.id)
      } else {
        const vector = decodeVectors.get(item.source.name)
        assert.equal(hex(encode(decode(Buffer.from(vector.historical_hex, 'hex')))), item.observed.canonicalHex, item.id)
        assert.equal(item.observed.canonicalHex, hex(encode(vector.decodes_to)), item.id)
      }
      assert.equal(item.observed.result, 'PASS')
    } else if (item.direction === 'encode') {
      labCases++
      assert.equal(item.origin, 'lab-derived')
      assert.equal(item.basis, 'required', item.id)
      assert.equal(hex(encode(materialize(item.input))), item.expected.encodedHex, item.id)
    } else {
      labCases++
      assert.equal(item.origin, 'lab-derived')
      const bytes = Buffer.from(item.input.hex, 'hex')
      for (const [expected, fn, mode] of [[item.expected, decode, 'semantic'], [item.informative.strict, decodeStrict, 'strict (informative)']]) {
        const reason = code(() => fn(bytes))
        if (expected.result === 'ACCEPT') {
          assert.equal(reason, null, `${item.id} ${mode}`)
          assert.equal(hex(encode(fn(bytes))), expected.canonicalHex, `${item.id} ${mode}`)
        } else assert.equal(reason, expected.reason, `${item.id} ${mode}`)
      }
    }
  }
  assert.equal(publishedCases, 44)
  assert.ok(labCases >= 30)
  // Only an outcome a text fixes may fail an implementation; the rest are laboratory choices.
  assert.ok(tags.required > 44 && tags.labChoice >= 15)
})

test('LAB_SELF_TEST_ONLY: map keys follow the bytewise order of their encodings, whatever their type or insertion order', () => {
  // 100 (18 64) < -1 (20) < "a" (61 61)
  assert.equal(hex(encode(new Map([['a', 1], [100, 2], [-1, 3]]))), 'a31864022003616101')
  assert.equal(hex(encode({ z: 1, aaa: 2 })), hex(encode(new Map([['aaa', 2], ['z', 1]]))))
  // The VA-ANC reference map: the deterministic order is not the order it is written in.
  const reference = encode({ v: 1, aid: 'A', tx: new Uint8Array([4]), out: 0, beef: new Uint8Array([3]) })
  assert.deepEqual([...decode(reference).keys()], ['v', 'tx', 'aid', 'out', 'beef'])
  assert.equal(hex(reference), 'a56176016274784104636169646141636f75740064626565664103')
})

test('LAB_SELF_TEST_ONLY: absent values, numbers outside the integer domain and erased types', () => {
  assert.equal(hex(encode(undefined)), 'f7')
  assert.equal(hex(encode([undefined, null])), '82f6f6')
  assert.equal(hex(encode({ a: undefined, b: null })), 'a16162f6')
  assert.equal(hex(encode(new Date(1786461096765))), '1b0000019ff1610b3d')
  assert.equal(hex(encode(new Set([3, 1, 2]))), '83010203')
  // Cross-checked against cbor-x 1.6.9 with the options the published suite names.
  assert.equal(hex(encode(-0)), '00')
  assert.equal(hex(encode(NaN)), 'fb7ff8000000000000')
  assert.equal(hex(encode(Infinity)), 'fb7ff0000000000000')
  assert.equal(hex(encode(-Infinity)), 'fbfff0000000000000')
  assert.equal(hex(encode(-(2 ** 53))), 'fbc340000000000000')
  assert.equal(hex(encode(Buffer.from([1, 2]))), '420102')
})

test('LAB_SELF_TEST_ONLY: the encoder refuses inputs outside the profile', () => {
  assert.equal(code(() => encode(1n)), 'bigint-input')
  assert.equal(code(() => encode('\ud800')), 'string-not-well-formed')
  assert.equal(code(() => encode(() => 1)), 'unsupported-type')
  assert.equal(code(() => encode(Symbol('s'))), 'unsupported-type')
  assert.equal(code(() => encode(new Uint16Array(1))), 'unsupported-type')
  assert.equal(code(() => encode(new (class Thing {})())), 'unsupported-type')
  assert.equal(code(() => encode({ [Symbol('k')]: 1 })), 'unsupported-type')
  assert.equal(code(() => encode(new Date(NaN))), 'unsupported-type')
  assert.equal(code(() => encode(new Map([[[1], 1], [[1], 2]]))), 'duplicate-key')
  assert.equal(code(() => encode(new Set([{}, {}]))), 'duplicate-set-member')
  assert.equal(code(() => encode(new Map([[undefined, 1]]))), 'unsupported-type')
  let deep = 0
  for (let i = 0; i < 80; i++) deep = [deep]
  assert.equal(code(() => encode(deep)), 'depth')
  const cyclic = []
  cyclic.push(cyclic)
  assert.equal(code(() => encode(cyclic)), 'depth')
})

test('LAB_SELF_TEST_ONLY: the decoders bound their work by the bytes supplied', () => {
  assert.equal(code(() => decode(Buffer.from('9bffffffffffffffff', 'hex'))), 'truncated')
  assert.equal(code(() => decode(Buffer.from('bb00000000ffffffff', 'hex'))), 'truncated')
  assert.equal(code(() => decode(Buffer.from('5b0000000100000000', 'hex'))), 'truncated')
  assert.equal(code(() => decode(Buffer.alloc(0))), 'truncated')
  assert.equal(code(() => decode(Buffer.from('81'.repeat(80) + '00', 'hex'))), 'depth')
  assert.equal(code(() => decode('a0')), 'input')
  assert.equal(code(() => decode(Buffer.from('5801ff', 'hex'))), null)
  assert.equal(isDeterministic(Buffer.from('5801ff', 'hex')), false)
  assert.equal(isDeterministic(Buffer.from('41ff', 'hex')), true)
  // A leading byte-order mark is text, not a marker to strip.
  assert.equal(hex(encode(decodeStrict(Buffer.from('63efbbbf', 'hex')))), '63efbbbf')
})
