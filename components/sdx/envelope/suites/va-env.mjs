// VA-ENV: SDX v0.1 record envelopes under the laboratory profile (ENV §2, §4-§15).
// Known-answer records written from frozen random values, the projections every reader
// role must reach on them, the writer's input refusals, the ENV §4 known answer, and a
// refusal corpus built clause by clause. LAB_SELF_TEST_ONLY.
import { b64u, hex, unb64u, utf8 } from '../lib/lab.mjs'
import { encode } from '../lib/cbor.mjs'
import { calculateSecrets } from '../lib/keys.mjs'
import { compressWithMarker } from '../lib/lzma.mjs'

const flipB64 = (text, at = 0) => { const b = Buffer.from(unb64u(text)); b[at] ^= 0x01; return b64u(b) }
const withByte = (text, at, value) => { const b = Buffer.from(unb64u(text)); b[at] = value; return b64u(b) }
const clone = value => structuredClone(value)

export function vaEnv(kit) {
  const { add, record, build, readReq, expectRead, refused } = kit

  // ---- known-answer records -------------------------------------------------------------
  // R1: every sensitivity, set and unset, audit recipients A and B, per-field recipients.
  const r1 = record('R1', {
    f: 'meterReading', mv: 1,
    fields: [
      { n: 'meterId', sn: 'pu', pl: 'ch', value: 'LAB-MTR-0001' },
      { n: 'kwh', sn: 'pr', pl: 'ch', value: 1234 },
      { n: 'interval', sn: 'au', pl: 'ch', value: { end: 1794790800000, start: 1794787200000 } },
      { n: 'site', sn: 'pr', pl: 'ch', value: { $bytes: hex(utf8('LAB_SELF_TEST_ONLY site reference')) } },
      { n: 'note', sn: 'au', pl: 'ch' },
      { n: 'comment', sn: 'pr', pl: 'ch' },
      { n: 'tag', sn: 'pu', pl: 'ch' }
    ],
    auditRecipients: ['A', 'B'],
    fieldRecipients: { kwh: ['A'], site: ['A', 'B'] }
  })
  // R2: one audit field, no external recipient: the writer self-recipient alone (ENV §5.2).
  const r2 = record('R2', { f: 'heartbeat', mv: 2, fields: [{ n: 'status', sn: 'au', pl: 'ch', value: 'ok' }], auditRecipients: [], fieldRecipients: {} })
  // R3: a writer-blind field (ENV §9.1) read by its external reader.
  const r3 = record('R3', {
    f: 'tokenIssue', mv: 1,
    fields: [
      { n: 'serial', sn: 'au', pl: 'ch', value: 'LAB-TOKEN-7' },
      { n: 'secret', sn: 'pr', pl: 'ch', value: 'LAB_SELF_TEST_ONLY blind content', blind: true },
      { n: 'memo', sn: 'pr', pl: 'ch', value: 'readable by the writer' }
    ],
    auditRecipients: ['A'],
    fieldRecipients: { secret: ['A'], memo: ['A'] }
  })
  // R4: a convergent field (ENV §4, §5.2, §6.1, §9): iter and salt at both layers.
  const r4 = record('R4', {
    f: 'documentFiled', mv: 1,
    fields: [
      { n: 'docRef', sn: 'au', pl: 'ch', value: 'LAB-DOC-42' },
      { n: 'photoHash', sn: 'pr', pl: 'ch', value: { $bytes: hex(utf8('LAB_SELF_TEST_ONLY photo hash')) }, cv: true }
    ],
    auditRecipients: ['A'],
    fieldRecipients: { photoHash: ['A'] }
  })
  // R5: an NFC field name given decomposed, the full private tuple, null, negative and nested values.
  const r5 = record('R5', {
    f: 'attachment', mv: 3,
    fields: [
      { n: 'café', sn: 'pr', pl: 'ch', value: { $bytes: '00ff10' }, filename: 'lab.bin', mediaType: 'application/octet-stream', meta: { pages: 1, tags: ['a', 'b'] } },
      { n: 'balance', sn: 'au', pl: 'ch', value: -42 },
      { n: 'nothing', sn: 'au', pl: 'ch', value: null },
      { n: 'onlyName', sn: 'pr', pl: 'ch', value: true, mediaType: 'application/cbor' }
    ],
    auditRecipients: ['A'],
    fieldRecipients: { 'café': ['A'], onlyName: ['A'] }
  })

  const kat = (req, title, basis, reads) => {
    const res = build(req)
    const writeId = add({
      title, basis, requirement: ['SDX-A-03', 'SDX-A-04'], tag: 'required', direction: 'write',
      request: req,
      expect: { envelope: hex(res.envelope), deterministic: kit.deterministic(req, res) }
    })
    for (const [who, as, why] of reads) {
      add({
        title: `${title}: read by ${kit.label(who, as)}. ${why}`,
        basis, requirement: [who === 'W' ? 'SDX-A-04' : 'SDX-A-03'], tag: 'required', direction: 'read', fromWrite: writeId,
        request: readReq(who, as, hex(res.envelope)),
        expect: expectRead(req, res, who)
      })
    }
    return res
  }
  const R1 = kat(r1, 'Known-answer record R1: public, audit and private fields, set and unset, two audit recipients and per-field recipient lists', ['ENV §2', 'ENV §5', 'ENV §6', 'ENV §7', 'ENV §8.1', 'ENV §8.6', 'ENV §9', 'ENV §12', 'ENV §13', 'ENV §14', 'ENV §15'], [
    ['W', 'writer', 'Holding only its root, the writer reaches every tier through its self-recipient slots (ENV §5.2, §12 self-replication).'],
    ['A', 'reader', 'A is on the outer wrap and on both private fields, so it reads everything.'],
    ['B', 'reader', 'B is on the outer wrap and on `site` only: `kwh` is redacted and the decode continues (ENV §9.1 rule 2, §15 rule 3).'],
    ['O', 'reader', 'O holds no slot: the Nothing tier, with `proto`, the public slots and `aid` from the protected header (ENV §12, §14 step 4).']
  ])
  const r2Spec = { f: 'heartbeat', mv: 2, fields: [{ n: 'status', sn: 'au', pl: 'ch', value: 'ok' }], auditRecipients: [], fieldRecipients: {} }
  const R2 = kat(r2, 'Known-answer record R2: one audit field and no external recipient; the outer wrap carries the writer self-recipient alone', ['ENV §5.2', 'ENV §12', 'ENV §13'], [
    ['W', 'writer', 'The self-recipient is the one access path (ENV §5.2).'],
    ['A', 'reader', 'A is not addressed and stays at the Nothing tier; the record has no public field.']
  ])
  kat(r3, 'Known-answer record R3: a writer-blind private field whose only recipient is A', ['ENV §9.1', 'ENV §12', 'ENV §15'], [
    ['W', 'writer', 'The writer keeps the audit tier and every other field, and its resolver declines the blind field, which surfaces as redacted (ENV §9.1 rule 2, §12).'],
    ['A', 'reader', 'A reads the blind field through its own slot.']
  ])
  const R4 = kat(r4, 'Known-answer record R4: a convergent private field; the outer protected header carries iter and salt, and both layers carry an A256GCMKW slot', ['ENV §4', 'ENV §5.2', 'ENV §6.1', 'ENV §9', 'ENV §11', 'ENV §16'], [
    ['W', 'writer', 'The identity slots open it; the convergent slots are not offered to the key resolver (ENV §5.2, §9.1 rule 2(a)).'],
    ['A', 'reader', 'A reads the convergent field through its identity slot.']
  ])
  kat(r5, 'Known-answer record R5: a field name given in decomposed form (stored and derived in NFC), the full private tuple, a null audit value and a negative integer', ['ENV §3', 'ENV §6.1', 'ENV §9', 'KEYS §1.6.2'], [
    ['W', 'writer', 'The descriptor carries the NFC name and the field key derives from it.'],
    ['A', 'reader', 'A recovers value, filename, media type and meta from the tuple.'],
    ['B', 'reader', 'B is not addressed: the Nothing tier, with no public field.']
  ])

  // ---- writer input refusals (ENV §6.1, §7.1, §9, §9.1, §13; KEYS §1.6.2) ------------------
  const writeRefusal = (title, basis, fields, fieldRecipients, detail) => {
    const req = record(`WR-${detail}`, { f: 'refused', mv: 1, fields, auditRecipients: ['A'], fieldRecipients }, { noRandom: true })
    add({ title, basis, requirement: ['SDX-A-03'], tag: 'required', direction: 'write', request: req, expect: { refusal: { class: 'write-refused', detail } } })
  }
  writeRefusal('A writer-blind private field with no external recipient is refused at write time', ['ENV §9.1 rule 1', 'ENV §9'], [{ n: 'hidden', sn: 'pr', pl: 'ch', value: 1, blind: true }], {}, 'blind-without-recipient')
  writeRefusal('An unset private field placed off the envelope is refused (unrepresentable)', ['ENV §7.1', 'ENV §13 step 4'], [{ n: 'later', sn: 'pr', pl: 'ov' }], {}, 'unset-externalised-private')
  writeRefusal('An unset private field that supplies a filename is refused (orphaned metadata)', ['ENV §7.1', 'ENV §13 step 4'], [{ n: 'later', sn: 'pr', pl: 'ch', filename: 'x.txt' }], {}, 'unset-with-metadata')
  writeRefusal('A field name used by a public and a private field is refused', ['ENV §6.1'], [{ n: 'x', sn: 'pu', pl: 'ch', value: 1 }, { n: 'x', sn: 'pr', pl: 'ch', value: 2 }], {}, 'duplicate-field-name')
  writeRefusal('Two names equal after NFC normalisation are one name, and are refused as a duplicate', ['ENV §6.1', 'KEYS §1.6.2'], [{ n: 'café', sn: 'au', pl: 'ch', value: 1 }, { n: 'café', sn: 'au', pl: 'ch', value: 2 }], {}, 'duplicate-field-name')
  writeRefusal('`cv` on an audit field is refused, not ignored', ['ENV §6.1 rules 2 and 3', 'ENV §4'], [{ n: 'a', sn: 'au', pl: 'ch', value: 1, cv: true }], {}, 'cv-not-private')
  writeRefusal('`cv: false` is refused: absent is the only spelling of off', ['ENV §6.1 rules 1 and 3'], [{ n: 'p', sn: 'pr', pl: 'ch', value: 1, cv: false }], {}, 'cv-not-true')
  writeRefusal('A field name containing `/` is refused at construction, never escaped', ['KEYS §1.6.2'], [{ n: 'a/b', sn: 'au', pl: 'ch', value: 1 }], {}, 'field-name-separator')
  writeRefusal('A writer-blind field that declares `cv` is refused', ['ENV §9.1 rule 5'], [{ n: 'hidden', sn: 'pr', pl: 'ch', value: 1, blind: true, cv: true }], { hidden: ['A'] }, 'blind-cv')
  writeRefusal('A field name longer than 256 bytes is refused', ['KEYS §1.6.2'], [{ n: 'n'.repeat(257), sn: 'au', pl: 'ch', value: 1 }], {}, 'field-name-length')

  // ---- ENV §4 known answers ----------------------------------------------------------------
  const secretsCase = (title, data, iterations) => {
    const s = iterations >= 200000 ? calculateSecrets(data, iterations) : null
    add({
      title, basis: ['ENV §4'], requirement: ['SDX-A-03'], tag: 'required', direction: 'hook',
      request: { op: 'secrets', data: hex(data), iterations },
      expect: s ? { hash: hex(s.hash), s1: hex(s.s1), s2: hex(s.s2), cek: hex(s.cek) } : { refusal: { class: 'input', detail: 'iterations-below-floor' } },
      ...(s ? { oracle: { reversedOrder: hex(s.reversed), note: 'HMAC-SHA-256(key = s1, message = s2), the value a reversed implementation produces; it must never equal cek' } } : {})
    })
  }
  secretsCase('ENV §4 known answer: calculateSecrets over a fixed text, the HMAC key s2 and the message s1', utf8('LAB_SELF_TEST_ONLY ENV §4 known answer'), 200000)
  secretsCase('ENV §4 known answer over the plaintext tuple of R4\'s convergent field', encode([utf8('LAB_SELF_TEST_ONLY photo hash')]), 200000)
  secretsCase('ENV §4: an iteration count below 200000 is refused rather than derived', utf8('LAB_SELF_TEST_ONLY ENV §4 known answer'), 199999)

  // ---- read refusals, clause by clause ------------------------------------------------------
  // Each mutates one stage of a fresh R1-shaped record and leaves every other stage conforming.
  const base = name => record(name, { ...r1Spec })
  const r1Spec = {
    f: 'meterReading', mv: 1,
    fields: clone(r1.record.fields),
    auditRecipients: ['A', 'B'],
    fieldRecipients: { kwh: ['A'], site: ['A', 'B'] }
  }
  const refusal = ({ title, basis, hooks = {}, who = 'W', as, cls, detail, tag = 'required', classTag, expect, spec }) => {
    const req = spec ? record(`RF-${kit.count()}`, spec) : base(`RF-${kit.count()}`)
    const res = build(req, hooks)
    add({
      title, basis, requirement: ['SDX-A-03'], tag, ...(classTag ? { classTag } : {}), direction: 'read',
      request: readReq(who, as ?? (who === 'W' ? 'writer' : 'reader'), hex(res.envelope)),
      expect: expect ? expect(req, res) : refused(cls, detail)
    })
  }
  const env = fn => ({ envelope: e => { const c = { ...e }; fn(c); return c } })

  // ENV §2, §3, §14 steps 1-2.
  refusal({ title: 'A `proto` that is not the configured format identifier (the example profile\'s `sdx:record:v1`) is refused', basis: ['ENV §2', 'ENV §14 step 2'], hooks: env(e => { e.proto = 'sdx:record:v1' }), cls: 'format', detail: 'proto', classTag: 'labChoice' })
  refusal({ title: 'An envelope with no `proto` is refused', basis: ['ENV §2', 'ENV §14 step 2'], hooks: env(e => { delete e.proto }), cls: 'format', detail: 'proto', classTag: 'labChoice' })
  refusal({ title: 'Truncated envelope bytes are refused', basis: ['ENV §3', 'ENV §14 step 1'], hooks: { bytes: b => b.subarray(0, b.length - 1) }, cls: 'format', detail: 'envelope-cbor:truncated', classTag: 'labChoice' })
  refusal({ title: 'A tagged envelope is refused', basis: ['ENV §3 rule 4'], hooks: { bytes: b => Uint8Array.from([0xd8, 0x18, ...b]) }, cls: 'format', detail: 'envelope-cbor:tag', classTag: 'labChoice' })
  refusal({ title: 'An indefinite-length envelope map is refused', basis: ['ENV §3 rule 5'], hooks: { bytes: b => Uint8Array.from([0xbf, ...b.subarray(1), 0xff]) }, cls: 'format', detail: 'envelope-cbor:indefinite-length', classTag: 'labChoice' })
  refusal({ title: 'An envelope member outside {proto, pu, outer} is not judged before the unwrap, and the record decodes (laboratory choice: ENV §2 states no rule for other members, and ANC §11.1 makes the keyless admission gate, which does not look at them, the reader\'s pre-unwrap gate)', basis: ['ENV §2', 'ANC §11.1'], hooks: env(e => { e.x = 1 }), tag: 'labChoice', expect: (req, res) => expectRead(req, res, 'W') })
  refusal({ title: 'A `pu` that is not an array is refused', basis: ['ENV §2', 'ANC §11.1'], hooks: env(e => { e.pu = {} }), cls: 'format', detail: 'pu', classTag: 'labChoice' })
  refusal({ title: 'An outer JWE without its authentication tag is refused', basis: ['ENV §2', 'ANC §11.1'], hooks: { outer: o => { const c = { ...o }; delete c.tag; return c } }, cls: 'format', detail: 'outer-shape', classTag: 'labChoice' })

  // ENV §5.3, §14 step 5a, §17.5.
  refusal({ title: 'An outer protected header without `aid` is refused as an integrity failure', basis: ['ENV §5.3'], hooks: { outerProtected: p => { const c = { ...p }; delete c.aid; return c } }, cls: 'integrity', detail: 'protected-aid' })
  refusal({ title: 'An outer protected-header `aid` that is not text is refused as an integrity failure', basis: ['ENV §5.3'], hooks: { outerProtected: p => ({ ...p, aid: 12345 }) }, cls: 'integrity', detail: 'protected-aid' })
  refusal({ title: 'An outer protected-header `aid` that differs from the header\'s own `aid` is refused after the outer decrypt as an integrity failure (spliced records)', basis: ['ENV §5.3', 'ENV §14 step 5a'], hooks: { protectedAid: () => kit.otherAid, outerProtected: p => ({ ...p, aid: kit.otherAid }) }, cls: 'integrity', detail: 'aid-mismatch' })
  refusal({ title: 'A flipped byte of the outer ciphertext fails the outer authentication tag: integrity failure', basis: ['ENV §17.5', 'ENV §14 step 4'], hooks: { outer: o => ({ ...o, ciphertext: flipB64(o.ciphertext, 3) }) }, cls: 'integrity', detail: 'outer:decrypt' })
  refusal({ title: 'A flipped byte of the outer authentication tag: integrity failure', basis: ['ENV §17.5'], hooks: { outer: o => ({ ...o, tag: flipB64(o.tag, 0) }) }, cls: 'integrity', detail: 'outer:decrypt' })
  refusal({ title: 'A flipped byte of the writer\'s wrapped key on the outer wrap: integrity failure', basis: ['ENV §17.5', 'ENV §16'], hooks: { outer: o => ({ ...o, recipients: o.recipients.map((r, i) => i === 0 ? { ...r, encrypted_key: flipB64(r.encrypted_key, 5) } : r) }) }, cls: 'integrity', detail: 'outer:decrypt' })
  refusal({ title: 'An outer protected header altered after encryption (a member added) breaks the authentication tag, which covers it: integrity failure', basis: ['ENV §5.3', 'ENV §17.5'], hooks: { outer: o => ({ ...o, protected: b64u(utf8(JSON.stringify({ ...JSON.parse(Buffer.from(o.protected, 'base64url').toString()), zz: 1 }))) }) }, cls: 'integrity', detail: 'outer:decrypt' })
  refusal({ title: 'An off-curve ephemeral key in the writer\'s outer slot: integrity failure', basis: ['ENV §9.1 rule 2', 'ENV §16'], hooks: { outer: o => ({ ...o, recipients: o.recipients.map((r, i) => i === 0 ? { ...r, header: { ...r.header, epk: { ...r.header.epk, y: flipB64(r.header.epk.y, 31) } } } : r) }) }, cls: 'integrity', detail: 'outer:epk' })
  refusal({
    title: 'An outer protected-header `aid` replaced after encryption: the reader\'s one candidate key, derived from it, matches no slot, so the reader stays at the Nothing tier (laboratory outcome: no slot is tried, so nothing is refused)', basis: ['ENV §5.3', 'ENV §14 step 4'], tag: 'labChoice',
    hooks: { outer: o => ({ ...o, protected: b64u(utf8(JSON.stringify({ ...JSON.parse(Buffer.from(o.protected, 'base64url').toString()), aid: kit.otherAid }))) }) },
    expect: (req, res) => ({ ...expectRead(req, res, 'O'), aid: kit.otherAid })
  })

  // ENV §6, §6.1.
  refusal({ title: 'An audit layer carrying a top-level member outside {hdr, sigs, au, pr} is refused', basis: ['ENV §6', 'ENV §14 step 5'], hooks: { audit: a => ({ ...a, x: 1 }) }, cls: 'structure', detail: 'audit-member', classTag: 'labChoice' })
  refusal({ title: 'An audit layer without `pr` is refused (laboratory choice: ENV §6 shows the member and states no decoder rule for its absence)', basis: ['ENV §6'], hooks: { audit: a => { const c = { ...a }; delete c.pr; return c } }, cls: 'structure', detail: 'audit-missing-pr', tag: 'labChoice' })
  refusal({ title: 'Audit-layer bytes that are not CBOR are refused (laboratory class: decode)', basis: ['ENV §14 step 5'], hooks: { auditBytes: () => Uint8Array.of(0xff) }, cls: 'decode', detail: 'audit-cbor:not-well-formed', classTag: 'labChoice' })
  refusal({ title: '`pks` outside {root, delegate} is refused', basis: ['ENV §6.1'], hooks: { hdr: h => ({ ...h, pks: 'admin' }) }, cls: 'structure', detail: 'pks', classTag: 'labChoice' })
  refusal({ title: 'A descriptor `pl` outside {ch, ov, ex} is refused', basis: ['ENV §6.1'], hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'interval' ? { ...d, pl: 'zz' } : d) }) }, cls: 'structure', detail: 'pl', classTag: 'labChoice' })
  refusal({ title: 'A descriptor `sn` outside {pu, au, pr} is refused (laboratory choice: ENV §6.1 lists the values and names a decoder rule only for `pks` and `pl`)', basis: ['ENV §6.1'], tag: 'labChoice', hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'interval' ? { ...d, sn: 'xx' } : d) }) }, cls: 'structure', detail: 'sn' })
  refusal({ title: 'One field name declared for an audit and a private field is refused at the descriptor-to-slot cross-check', basis: ['ENV §6.1'], hooks: { hdr: h => ({ ...h, fields: [...h.fields, { n: 'kwh', sn: 'au', pl: 'ch' }] }), slots: s => ({ ...s, au: [...s.au, { n: 'kwh', v: 1 }] }) }, cls: 'structure', detail: 'duplicate-field-name', classTag: 'labChoice' })
  refusal({ title: '`cv: false` on a descriptor is refused', basis: ['ENV §6.1 rules 1 and 3'], hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'kwh' ? { ...d, cv: false } : d) }) }, cls: 'structure', detail: 'cv-not-true', classTag: 'labChoice' })
  refusal({ title: '`cv: true` on an audit descriptor is refused', basis: ['ENV §6.1 rule 2'], hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'interval' ? { ...d, cv: true } : d) }) }, cls: 'structure', detail: 'cv-not-private', classTag: 'labChoice' })
  refusal({ title: '`cv: true` on a private field whose slot carries no convergent material is refused after signature verification', basis: ['ENV §6.1 rules 5 and 7'], hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'kwh' ? { ...d, cv: true } : d) }) }, cls: 'structure', detail: 'cv-backing-field', classTag: 'labChoice' })
  refusal({ title: 'The header field `ds` missing is refused (laboratory choice: ENV §6.1 shows it without `?`)', basis: ['ENV §6.1'], tag: 'labChoice', hooks: { hdr: h => { const c = { ...h }; delete c.ds; return c } }, cls: 'structure', detail: 'hdr-ds' })

  // Convergent backing (ENV §6.1 rules 5, 6, 8) on R4-shaped records.
  const cvRecord = (title, basis, hooks, cls, detail, opts = {}) => {
    const req = record(`CV-${kit.count()}`, { ...r4Spec })
    const res = build(req, hooks)
    add({
      title, basis, requirement: ['SDX-A-03'], tag: opts.tag ?? 'required', ...(opts.classTag ? { classTag: opts.classTag } : {}), direction: 'read',
      request: readReq('A', 'reader', hex(res.envelope)),
      expect: opts.expect ? opts.expect(req, res) : refused(cls, detail)
    })
  }
  const r4Spec = { f: 'documentFiled', mv: 1, fields: clone(r4.record.fields).map(f => ({ ...f })), auditRecipients: ['A'], fieldRecipients: { photoHash: ['A'] } }
  cvRecord('A convergent slot whose protected `iter` is below 200000 is refused', ['ENV §6.1 rule 6'], { fieldProtected: p => ('iter' in p ? { ...p, iter: 1000 } : p) }, 'structure', 'cv-backing-field', { classTag: 'labChoice' })
  cvRecord('A convergent slot with an empty `salt` is refused', ['ENV §6.1 rule 6'], { fieldProtected: p => ('salt' in p ? { ...p, salt: '' } : p) }, 'structure', 'cv-backing-field', { classTag: 'labChoice' })
  cvRecord('A `cv` field fully backed while the outer wrap carries no convergent material is refused (the test is conjunctive at both layers)', ['ENV §6.1 rule 5'], {
    outerProtected: p => { const c = { ...p }; delete c.iter; delete c.salt; return c },
    outer: o => ({ ...o, recipients: o.recipients.filter(r => r.header.alg !== 'A256GCMKW') })
  }, 'structure', 'cv-backing-outer', { classTag: 'labChoice' })
  cvRecord('Convergent material without any `cv` descriptor, the shape of an earlier format generation, still decodes', ['ENV §6.1 rule 8', 'ENV §17.7'], { hdr: h => ({ ...h, fields: h.fields.map(d => { const c = { ...d }; delete c.cv; return c }) }) }, null, null, {
    expect: (req, res) => expectRead(req, res, 'A')
  })

  // ENV §7: the unset marker.
  const slotEdit = (array, name, fn) => ({ slots: s => ({ ...s, [array]: s[array].map(x => x.n === name ? fn({ ...x }) : x) }) })
  refusal({ title: 'A public slot carrying neither a value nor the marker is refused, even by an observer at the Nothing tier', basis: ['ENV §7 rule 1', 'ENV §14 step 3'], who: 'O', hooks: slotEdit('pu', 'tag', () => ({ n: 'tag' })), cls: 'structure', detail: 'slot-without-value', classTag: 'labChoice' })
  refusal({ title: 'An audit slot carrying neither a value nor the marker is refused', basis: ['ENV §7 rule 1'], hooks: slotEdit('au', 'note', () => ({ n: 'note' })), cls: 'structure', detail: 'slot-without-value', classTag: 'labChoice' })
  refusal({ title: 'A public marker slot that also carries a value is refused, at the Nothing tier too', basis: ['ENV §7 rule 2', 'ENV §14 step 3'], who: 'O', hooks: slotEdit('pu', 'tag', () => ({ n: 'tag', u: true, v: 'x' })), cls: 'structure', detail: 'marker-with-value', classTag: 'labChoice' })
  refusal({ title: 'An audit marker slot that also carries a value is refused', basis: ['ENV §7 rule 2'], hooks: slotEdit('au', 'note', () => ({ n: 'note', u: true, v: 1 })), cls: 'structure', detail: 'marker-with-value', classTag: 'labChoice' })
  refusal({ title: 'A private marker slot that also carries a JWE is refused', basis: ['ENV §7 rule 2', 'ENV §7.1'], hooks: { slots: s => ({ ...s, pr: s.pr.map(x => x.n === 'comment' ? { n: 'comment', u: true, jwe: s.pr.find(y => y.n === 'kwh').jwe } : x) }) }, cls: 'structure', detail: 'marker-with-value', classTag: 'labChoice' })
  refusal({ title: '`u: false` is refused', basis: ['ENV §7 rule 3'], hooks: slotEdit('au', 'note', () => ({ n: 'note', u: false })), cls: 'structure', detail: 'marker-not-true', classTag: 'labChoice' })
  refusal({ title: '`u: 1` is refused', basis: ['ENV §7 rule 3'], hooks: slotEdit('au', 'note', () => ({ n: 'note', u: 1 })), cls: 'structure', detail: 'marker-not-true', classTag: 'labChoice' })
  refusal({ title: 'The marker on a descriptor placed `ov` is refused: the marker is in-record only', basis: ['ENV §7 rule 3'], hooks: { hdr: h => ({ ...h, fields: h.fields.map(d => d.n === 'note' ? { ...d, pl: 'ov' } : d) }) }, cls: 'structure', detail: 'marker-not-in-record', classTag: 'labChoice' })
  refusal({ title: 'A marker slot with a member outside {n, u} is refused', basis: ['ENV §7 rule 4'], hooks: slotEdit('au', 'note', () => ({ n: 'note', u: true, x: 1 })), cls: 'structure', detail: 'marker-members', classTag: 'labChoice' })

  // ENV §8.1.
  refusal({ title: 'An audit slot mixing an in-record value and a manifest is refused', basis: ['ENV §8.1'], hooks: slotEdit('au', 'interval', x => ({ ...x, im: { sha: new Uint8Array(32), u: 'file:///lab', sz: 1 } })), cls: 'structure', detail: 'slot-mixes-members', classTag: 'labChoice' })
  refusal({ title: 'Two audit slots with one name are refused', basis: ['ENV §8.1'], hooks: { slots: s => ({ ...s, au: [...s.au, s.au[0]] }) }, cls: 'structure', detail: 'duplicate-au-slot', classTag: 'labChoice' })
  refusal({ title: 'An audit slot not named in `hdr.fields` is refused', basis: ['ENV §8.1'], hooks: { slots: s => ({ ...s, au: [...s.au, { n: 'ghost', v: 1 }] }) }, cls: 'structure', detail: 'undeclared-slot', classTag: 'labChoice' })
  refusal({ title: 'A declared field with no slot is refused (laboratory choice: ENV §8.1 refuses undeclared slots, and the text is silent on a descriptor without one)', basis: ['ENV §7', 'ENV §8.1', 'ENV §14 step 11'], tag: 'labChoice', hooks: { slots: s => ({ ...s, au: s.au.filter(x => x.n !== 'note') }) }, cls: 'structure', detail: 'descriptor-without-slot' })
  refusal({ title: 'A private field\'s slot placed in the audit array is refused (laboratory choice)', basis: ['ENV §6.1', 'ENV §8.1'], tag: 'labChoice', hooks: { slots: s => ({ ...s, au: [...s.au, s.pr.find(x => x.n === 'kwh')], pr: s.pr.filter(x => x.n !== 'kwh') }) }, cls: 'structure', detail: 'slot-sensitivity' })

  // ENV §9.1 rule 2: a decline is honoured only for a structurally valid slot. B is not a
  // recipient of `kwh`, so its resolver declines it; each malformation is an integrity refusal.
  const kwh = fn => ({ fieldJwe: (j, name) => (name === 'kwh' ? fn(clone(j)) : j) })
  const declined = (title, basis, hooks, detail) => refusal({ title, basis, who: 'B', hooks, cls: 'integrity', detail })
  declined('A private JWE with no recipient list is refused, not surfaced as redacted', ['ENV §9.1 rule 2'], kwh(j => ({ ...j, recipients: [] })), 'recipient-less')
  declined('A declined slot whose recipient identifier is not a P-256 point is refused', ['ENV §9.1 rule 2'], kwh(j => { j.recipients[1].header.kid = '02' + 'ff'.repeat(32); return j }), 'slot-validation:kid-point')
  declined('A declined slot whose `enc` is not A256GCM is refused', ['ENV §9.1 rule 2', 'ENV §16'], { fieldProtected: (p, name) => (name === 'kwh' ? { ...p, enc: 'A128GCM' } : p) }, 'slot-validation:enc')
  declined('A declined slot whose IV is not 12 bytes is refused', ['ENV §9.1 rule 2'], kwh(j => ({ ...j, iv: b64u(new Uint8Array(16)) })), 'slot-validation:iv-length')
  declined('A declined slot whose tag is not 16 bytes is refused', ['ENV §9.1 rule 2'], kwh(j => ({ ...j, tag: b64u(unb64u(j.tag).subarray(0, 15)) })), 'slot-validation:tag-length')
  declined('A declined slot whose effective header repeats a parameter across the protected and recipient levels is refused', ['ENV §9.1 rule 2', 'RFC 7516 §7.2.1'], { fieldProtected: (p, name) => (name === 'kwh' ? { ...p, alg: 'ECDH-ES+A256KW' } : p) }, 'slot-validation:header-union-repeats')
  declined('A declined slot whose wrapped key is not 40 bytes is refused', ['ENV §9.1 rule 2'], kwh(j => { j.recipients[1].encrypted_key = b64u(new Uint8Array(32)); return j }), 'slot-validation:encrypted_key-length')
  declined('A declined slot whose ephemeral key carries a private component is refused', ['ENV §9.1 rule 2'], kwh(j => { j.recipients[1].header.epk.d = b64u(new Uint8Array(32).fill(1)); return j }), 'slot-validation:epk')
  declined('A declined slot whose ephemeral key is off the curve is refused', ['ENV §9.1 rule 2'], kwh(j => { j.recipients[1].header.epk.y = flipB64(j.recipients[1].header.epk.y, 31); return j }), 'slot-validation:epk')
  declined('A declined slot whose ciphertext is not canonical base64url is refused', ['ENV §9.1 rule 2'], kwh(j => ({ ...j, ciphertext: j.ciphertext + '=' })), 'slot-validation:base64url-ciphertext')
  refusal({
    title: 'An authorised reader takes the ordinary route: the writer opens `kwh` through its own first slot although a later slot is malformed (the decline precondition binds the decline, not the decode)', basis: ['ENV §9.1 rule 2'],
    hooks: kwh(j => { j.recipients[1].header.kid = '02' + 'ff'.repeat(32); return j }),
    expect: (req, res) => expectRead(req, res, 'W')
  })

  // Tampering on the inner layer; declining never attempts a key (ENV §9.1 rule 2(b), §15 rule 3).
  refusal({ title: 'A flipped byte of `kwh`\'s ciphertext, read by its recipient A: the decryption step fails and the whole decode aborts with an integrity failure', basis: ['ENV §9.1 rule 2(b)', 'ENV §15 rule 3'], who: 'A', hooks: kwh(j => ({ ...j, ciphertext: flipB64(j.ciphertext, 2) })), cls: 'integrity', detail: 'field kwh:decrypt' })
  refusal({
    title: 'The same flipped ciphertext, read by B, which is not a recipient of `kwh`: B declines without attempting a key, so `kwh` is redacted and the record decodes', basis: ['ENV §9.1 rule 2', 'ENV §12', 'ENV §15 rule 3'], who: 'B',
    hooks: kwh(j => ({ ...j, ciphertext: flipB64(j.ciphertext, 2) })),
    expect: (req, res) => expectRead(req, res, 'B')
  })
  refusal({ title: 'A flipped byte of A\'s wrapped key on `kwh`, read by A: integrity failure', basis: ['ENV §9.1 rule 2(b)'], who: 'A', hooks: kwh(j => { j.recipients[1].encrypted_key = flipB64(j.recipients[1].encrypted_key, 1); return j }), cls: 'integrity', detail: 'field kwh:decrypt' })
  refusal({ title: 'A private plaintext that is not the tuple array is refused (laboratory class: decode)', basis: ['ENV §9', 'ENV §14 step 10'], who: 'A', hooks: { fieldPlaintext: (p, name) => (name === 'kwh' ? encode({ value: 1234 }) : p) }, cls: 'decode', detail: 'tuple-shape', classTag: 'labChoice' })
  refusal({ title: 'A corrupt LZMA stream under a valid tag is refused (laboratory class: decode)', basis: ['ENV §9', 'ENV §14 step 10'], who: 'A', hooks: { fieldCompressed: (c, name) => { if (name !== 'kwh') return c; const b = Uint8Array.from(c); b[13] ^= 0xff; return b } }, cls: 'decode', detail: 'lzma:corrupt', classTag: 'labChoice' })
  refusal({
    title: 'A private value compressed with the end-of-stream marker written still decodes (laboratory choice: readers are lenient; writers disable the marker, ENV §9)', basis: ['ENV §9'], who: 'A', tag: 'labChoice',
    hooks: { fieldCompressed: (c, name, plaintext) => (name === 'kwh' ? compressWithMarker(plaintext) : c) },
    expect: (req, res) => expectRead(req, res, 'A')
  })
  refusal({
    title: 'An outer wrap whose single recipient\'s ephemeral key sits in the protected header, as a stock JOSE library writes one recipient, still opens (laboratory choice for readers; writers keep the protected header to {enc, proto, aid}, ENV §5.2, §11)', basis: ['ENV §5.2', 'ENV §11'], tag: 'labChoice',
    spec: { ...r2Spec }, hooks: { outerEpkInProtected: true },
    expect: (req, res) => expectRead(req, res, 'W')
  })
  return { R1, R2, R4 }
}
