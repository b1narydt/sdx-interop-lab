// VA-SIG: SDX v0.1 record signatures (ENV §8.2-§8.5, §16; KEYS §1.8.3) and the signer
// binding a reader checks without a grant (KEYS §2.7.1, §2.7.2), on real record envelopes
// under the laboratory profile. LAB_SELF_TEST_ONLY.
import { b64u, hex, unb64u, utf8 } from '../lib/lab.mjs'
import { encode, encodeSuperseded } from '../lib/cbor.mjs'
import { rfc8949EncodeOptions, encode as cborgEncode } from 'cborg'
import { es256, highS } from '../lib/keys.mjs'
import { protectedSig, signingInput } from '../lib/jwe.mjs'

const flipB64 = (text, at = 0) => { const b = Buffer.from(unb64u(text)); b[at] ^= 0x01; return b64u(b) }
// A DER encoding of a P1363 signature (KEYS §1.8.3: verifiers MAY accept DER; ENV §16 fixes 64 bytes).
function der(sig) {
  const int = bytes => { let b = Buffer.from(bytes); while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([0x02, b.length]), b]) }
  const body = Buffer.concat([int(sig.subarray(0, 32)), int(sig.subarray(32))])
  return Uint8Array.from(Buffer.concat([Buffer.from([0x30, body.length]), body]))
}

export function vaSig(kit) {
  const { add, record, build, readReq, expectRead, refused } = kit
  const spec = {
    f: 'signedReading', mv: 1,
    fields: [
      { n: 'kind', sn: 'pu', pl: 'ch', value: 'LAB-KIND' },
      { n: 'reading', sn: 'au', pl: 'ch', value: 512 },
      { n: 'value', sn: 'pr', pl: 'ch', value: 'LAB_SELF_TEST_ONLY signed value' }
    ],
    auditRecipients: ['A'],
    fieldRecipients: { value: ['A'] }
  }
  const sigs = fn => ({ sigs: (s, ctx) => fn({ ...s, signatures: s.signatures.map(x => ({ ...x })) }, ctx) })
  const one = ({ title, basis, requirement = ['SDX-A-02'], hooks = {}, who = 'W', cls, detail, tag = 'required', classTag, expect }) => {
    const req = record(`SIG-${kit.count()}`, { ...spec, fields: spec.fields.map(f => ({ ...f })) })
    const res = build(req, hooks)
    add({
      title, basis, requirement, tag, ...(classTag ? { classTag } : {}), direction: 'read',
      request: readReq(who, who === 'W' ? 'writer' : 'reader', hex(res.envelope)),
      expect: expect ? expect(req, res) : refused(cls, detail)
    })
    return { req, res }
  }
  const accepted = (who, extra = {}) => (req, res) => ({ ...expectRead(req, res, who), ...extra(req, res) })

  // The signing kid known answer and the write-direction signature checks (ENV §8.2, §8.5).
  {
    const req = record('SIG-KAT', { ...spec, fields: spec.fields.map(f => ({ ...f })) })
    const res = build(req)
    const writeId = add({
      title: 'Known-answer signed record: one ES256 signature, detached payload, `kid` the hex of the per-record signing key derived from the writer\'s root, `hdr.pk` the same key', basis: ['ENV §8.2', 'ENV §8.5', 'ENV §16', 'KEYS §1.8.3', 'KEYS §2.7.1'],
      requirement: ['SDX-A-02'], tag: 'required', direction: 'write', request: req,
      expect: { envelope: hex(res.envelope), deterministic: kit.deterministic(req, res) }
    })
    for (const who of ['W', 'A']) {
      add({
        title: `The known-answer signed record, verified by ${kit.label(who, who === 'W' ? 'writer' : 'reader')}: it verifies on the current shape against the \`kid\` it names${who === 'W' ? ', and the root-holder re-derives that `kid` (ENV §8.5)' : '; a reader that does not hold the root cannot re-derive it'}`,
        basis: ['ENV §8.3', 'ENV §8.5', 'ENV §14 step 8'], requirement: ['SDX-A-02'], tag: 'required', direction: 'read', fromWrite: writeId,
        request: readReq(who, who === 'W' ? 'writer' : 'reader', hex(res.envelope)), expect: expectRead(req, res, who)
      })
    }
  }

  // ENV §8.3: the candidate list, current shape first, then the superseded integer shape once.
  const superseded = { signedBytes: (b, x) => encodeSuperseded(x), auditBytes: (b, x) => encodeSuperseded(x) }
  for (const who of ['W', 'A']) {
    one({ title: `A record written wholly under the superseded integer shape (\`tm\` as binary64) verifies on the second candidate, read by ${kit.label(who)}`, basis: ['ENV §8.3', 'ENV §3', 'VEC historical-float64-decode'], who, hooks: superseded, expect: accepted(who, (req, res) => ({ signature: { kid: res.derived.signing, shape: 'superseded' } })) })
  }
  one({ title: 'A superseded-shape audit layer whose signature covers the current shape verifies on the first candidate: candidates are rebuilt from decoded values, not lifted from the wire', basis: ['ENV §8.3'], hooks: { auditBytes: (b, x) => encodeSuperseded(x) }, expect: accepted('W', () => ({})) })
  one({ title: 'A signature over a non-deterministic encoding of {hdr, au, pr} (map keys in insertion order) verifies under neither candidate and is refused: failing closed is normative', basis: ['ENV §8.3', 'ENV §3 rule 1'], hooks: { signedBytes: (b, x) => cborgEncode({ pr: x.pr, hdr: x.hdr, au: x.au }, { ...rfc8949EncodeOptions, mapSorter: () => 0 }) }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A signature that covers only {hdr, au} is refused', basis: ['ENV §8.2', 'ENV §8.3'], hooks: { signedBytes: (b, x) => encode({ hdr: x.hdr, au: x.au }) }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A flipped bit in the signature is refused', basis: ['ENV §8.3'], hooks: sigs(s => { s.signatures[0].signature = flipB64(s.signatures[0].signature, 10); return s }), cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'The attached-payload value (the correct base64url of the signed bytes) in `payload` is refused as a signature failure', basis: ['ENV §8.2', 'ENV §8.3 step 2'], hooks: sigs((s, ctx) => ({ ...s, payload: b64u(ctx.signedBytes) })), cls: 'signature', detail: 'payload-not-empty' })
  one({ title: 'A `sigs` without `payload` is refused as a signature failure', basis: ['ENV §8.2', 'ENV §8.3 step 2'], hooks: sigs(s => { const c = { ...s }; delete c.payload; return c }), cls: 'signature', detail: 'payload-not-empty' })
  one({ title: 'An empty signature list is refused', basis: ['ENV §8.3'], hooks: sigs(s => ({ ...s, signatures: [] })), cls: 'signature', detail: 'empty-signature-list', classTag: 'labChoice' })
  one({ title: 'A signature whose protected header names `ES384` is not an ES256 signature and verifies nothing', basis: ['ENV §8.2', 'ENV §16'], hooks: { sigs: (s, ctx) => { const p = b64u(utf8(JSON.stringify({ alg: 'ES384', kid: ctx.kid }))); return { ...s, signatures: [{ protected: p, signature: b64u(es256(ctx.signer.d, signingInput(p, ctx.signedBytes))) }] } } }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A `kid` that is not a P-256 point verifies nothing', basis: ['ENV §8.5', 'ENV §16'], hooks: { sigKid: () => '02' + 'ff'.repeat(32) }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A `kid` naming another valid key (the writer\'s outer recipient key) than the signer verifies nothing', basis: ['ENV §8.3', 'ENV §8.5'], hooks: { sigKid: (k, ctx) => ctx.outerSelfKid }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A DER-encoded signature is refused (laboratory choice: KEYS §1.8.3 lets verifiers accept DER; ENV §16 fixes the 64-byte form)', basis: ['ENV §16', 'KEYS §1.8.3'], tag: 'labChoice', hooks: { signature: s => der(s) }, cls: 'signature', detail: 'no-signature-verifies' })
  one({ title: 'A high-S signature is valid and accepted', basis: ['KEYS §1.8.3'], tag: 'labChoice', hooks: { signature: s => highS(s) }, expect: accepted('W', () => ({})) })
  one({ title: 'A protected header serialised {kid, alg} verifies over the carried protected value', basis: ['ENV §8.2', 'ENV §8.3'], tag: 'labChoice', hooks: { sigs: (s, ctx) => { const p = b64u(utf8(JSON.stringify({ kid: ctx.kid, alg: 'ES256' }))); return { ...s, signatures: [{ protected: p, signature: b64u(es256(ctx.signer.d, signingInput(p, ctx.signedBytes))) }] } } }, expect: accepted('W', () => ({})) })
  one({ title: 'Two signature entries, the first invalid and the second valid: one signature verifies, so the record is accepted', basis: ['ENV §8.3 (step 3: reject only if no signature verifies)', 'ENV §14 step 8'], hooks: sigs(s => ({ ...s, signatures: [{ ...s.signatures[0], signature: flipB64(s.signatures[0].signature, 5) }, s.signatures[0]] })), expect: accepted('W', () => ({})) })

  // KEYS §2.7.1: root scope. hdr.pk is the per-record derived signing key, and the signature's kid is its hex.
  one({ title: 'A root record whose `hdr.pk` is not the key that signed it is refused as `root-pk-mismatch`', basis: ['KEYS §2.7.1'], requirement: ['SDX-A-02'], who: 'A', hooks: { hdr: (h, ctx) => ({ ...h, pk: ctx.otherKey }) }, cls: 'root-pk-mismatch', detail: 'pk-not-signer' })
  const stray = { signerKey: (d, ctx) => ctx.strayKey.d, sigKid: (k, ctx) => hex(ctx.strayKey.pub), hdr: (h, ctx) => ({ ...h, pk: ctx.strayKey.pub }) }
  one({ title: 'A root record signed by a key that is not derived from the writer\'s root, with `hdr.pk` and `kid` both naming it: the root-holder re-derives the expected `kid` and refuses `root-pk-mismatch`', basis: ['ENV §8.5', 'KEYS §2.7.1'], who: 'W', hooks: stray, cls: 'root-pk-mismatch', detail: 'kid-not-derived' })
  one({ title: 'The same record read by A, which does not hold the writer\'s root: the signature verifies against the `kid` it names and `hdr.pk` matches it; identity binding is a root-holder check (ENV §8.5)', basis: ['ENV §8.5', 'KEYS §2.7.1'], who: 'A', hooks: stray, expect: (req, res) => ({ ...expectRead(req, res, 'A'), hdr: { ...expectRead(req, res, 'A').hdr, pk: hex(res.extra.strayKey.pub) }, signature: { kid: hex(res.extra.strayKey.pub), shape: 'current' } }) })
  one({ title: 'A root record signed with the derived key of another record identifier is refused `root-pk-mismatch` by the root-holder', basis: ['ENV §8.5', 'KEYS §2.7.1'], who: 'W', hooks: { signerKey: (d, ctx) => ctx.otherRecordKey.d, sigKid: (k, ctx) => hex(ctx.otherRecordKey.pub), hdr: (h, ctx) => ({ ...h, pk: ctx.otherRecordKey.pub }) }, cls: 'root-pk-mismatch', detail: 'kid-not-derived' })
  one({ title: 'A root record carrying a delegation reference is refused `delegation-invalid` (mixed scope)', basis: ['KEYS §2.7.1'], hooks: { hdr: (h, ctx) => ({ ...h, dref: [ctx.delId] }) }, cls: 'delegation-invalid', detail: 'mixed-scope' })
  one({ title: 'A root record with no `dref` member is accepted: KEYS §2.7 has `dref` absent for root records, and the laboratory reads an empty `dref` the same way (reading 6)', basis: ['KEYS §2.7', 'KEYS §2.7.1', 'ENV §6.1'], tag: 'labChoice', hooks: { hdr: h => { const c = { ...h }; delete c.dref; return c } }, expect: accepted('W', () => ({})) })

  // KEYS §2.7.2, §2.14.1: delegate records are signed by the raw key pinned in the grant, and
  // their kid is hex(hdr.pk) (laboratory reading 4). The grant checks themselves belong to VA-GRANT.
  const delegate = (ctx, extra = {}) => ({ hdr: (h, c) => ({ ...h, pks: 'delegate', dref: [c.delId], pk: c.actor.pub, ...extra }), signerKey: (d, c) => c.actor.d, sigKid: (k, c) => hex(c.actor.pub) })
  const delegateExpect = who => (req, res) => {
    const base = expectRead(req, res, who)
    return { ...base, hdr: { ...base.hdr, pks: 'delegate', pk: hex(res.extra.actor.pub), dref: [hex(res.extra.delId)] }, signature: { kid: hex(res.extra.actor.pub), shape: 'current' } }
  }
  for (const who of ['W', 'A']) one({ title: `A delegate-signed record: \`pks\` delegate, \`dref\` [delId], \`hdr.pk\` the actor's pinned key, \`kid\` its hex; read by ${kit.label(who)}`, basis: ['KEYS §2.7.2', 'KEYS §2.14.1', 'ENV §8.5'], who, hooks: delegate(), expect: delegateExpect(who) })
  one({ title: 'A delegate record whose signature `kid` is the derived per-record key (the ENV §8.5 recipe) rather than `hdr.pk` is refused `delegation-invalid`', basis: ['KEYS §2.7.2', 'ENV §8.5'], hooks: { hdr: (h, c) => ({ ...h, pks: 'delegate', dref: [c.delId], pk: c.actor.pub }) }, cls: 'delegation-invalid', detail: 'signer-binding' })
  one({ title: 'A delegate record with an empty `dref` is refused `delegation-invalid` (bad-dref-length)', basis: ['KEYS §2.7.2'], hooks: { ...delegate(), hdr: (h, c) => ({ ...h, pks: 'delegate', dref: [], pk: c.actor.pub }) }, cls: 'delegation-invalid', detail: 'bad-dref-length' })
  one({ title: 'A delegate record whose delegation chain has length 2 is refused `delegation-invalid`', basis: ['KEYS §2.2', 'KEYS §2.7.2', 'ENV §6.1'], hooks: { ...delegate(), hdr: (h, c) => ({ ...h, pks: 'delegate', dref: [c.delId, c.delId2], pk: c.actor.pub }) }, cls: 'delegation-invalid', detail: 'bad-dref-length' })
  one({ title: 'A delegate record carrying two verifying signatures (the actor\'s and the derived root key\'s) is refused `delegation-invalid`: exactly one is required', basis: ['KEYS §2.7.2'], hooks: { ...delegate(), sigs: (s, c) => { const p = protectedSig(c.derivedKid); return { ...s, signatures: [...s.signatures, { protected: p, signature: b64u(es256(c.signer.d, signingInput(p, c.signedBytes))) }] } } }, cls: 'delegation-invalid', detail: 'signer-binding' })
  one({ title: 'A delegate record whose `kid` names the pinned key but whose signature was made by another key verifies nothing', basis: ['ENV §8.3', 'KEYS §2.7.2'], hooks: { ...delegate(), signerKey: (d, c) => c.strayKey.d }, cls: 'signature', detail: 'no-signature-verifies' })
}
