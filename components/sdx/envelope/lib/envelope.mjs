// The laboratory record writer: the ENV §13 encode flow under the laboratory profile, with
// every random value taken from the request's `random` member (frozen in frozen.json), and
// hooks that let a refusal case alter one stage while every other stage stays conforming.
// In-record placement only (pl "ch"); field placement (ENV §10, ENV-FP) is not authored.
import { p256 } from '@noble/curves/nist.js'
import { FORMAT, b64u, fail, fieldId, hex, outerId, signId, unhex, utf8 } from './lab.mjs'
import { MIN_ITERATIONS, calculateSecrets, es256, p256Self, p256Theirs, split } from './keys.mjs'
import { encode, fromJson } from './cbor.mjs'
import { ECDH, GCMKW, buildJwe, protectedSig, signingInput } from './jwe.mjs'
import { compress } from './lzma.mjs'

export class WriterRefusal extends Error {
  constructor(detail) { super(detail); this.detail = detail }
}
const refuse = detail => { throw new WriterRefusal(detail) }
const id = x => x
// Request maps are keyed by the field name as the caller spelled it; look them up by NFC form.
const lookup = (map, name) => { for (const [key, value] of Object.entries(map ?? {})) if (key.normalize('NFC') === name) return value; return undefined }

// Writer-side input rules, in the order ENV §13 and KEYS §1.6.2 state them.
export function checkWriteRequest(request) {
  const fields = request.record.fields
  const seen = new Set()
  for (const field of fields) {
    const name = field.n.normalize('NFC') // KEYS §1.6.2, ENV §6.1: names are NFC-normalised
    const bytes = utf8(name).length
    if (bytes < 1 || bytes > 256) refuse('field-name-length') // KEYS §1.6.2: 1 to 256 bytes
    if (name.includes('/')) refuse('field-name-separator') // KEYS §1.6.2: reject, never escape
    if (seen.has(name)) refuse('duplicate-field-name') // ENV §6.1
    seen.add(name)
    if (!['pu', 'au', 'pr'].includes(field.sn)) refuse('sensitivity')
    if (!['ch', 'ov', 'ex'].includes(field.pl)) refuse('placement')
    if ('cv' in field) {
      if (field.cv !== true) refuse('cv-not-true') // ENV §6.1 rule 1
      if (field.sn !== 'pr') refuse('cv-not-private') // ENV §6.1 rule 2
    }
    if (field.blind === true) {
      if (field.sn !== 'pr') refuse('blind-not-private') // ENV §9.1: a private field MAY be blind
      if ('cv' in field) refuse('blind-cv') // ENV §9.1 rule 5
      if ((lookup(request.fieldRecipients, name) ?? []).length === 0) refuse('blind-without-recipient') // ENV §9.1 rule 1
    }
    const unset = !('value' in field)
    if (field.sn === 'pr') {
      if (unset) {
        if (field.pl !== 'ch') refuse('unset-externalised-private') // ENV §7.1, §13 step 4
        if ('filename' in field || 'mediaType' in field || 'meta' in field) refuse('unset-with-metadata') // ENV §7.1
      } else {
        const count = (field.cv === true ? 1 : 0) + (field.blind === true ? 0 : 1) + (lookup(request.fieldRecipients, name) ?? []).length
        if (count === 0) refuse('unopenable-slot') // ENV §9, §13 step 4
      }
    }
    if (field.pl !== 'ch') refuse('placement-not-authored') // laboratory writer: in-record only
  }
}

// ENV §9: the private plaintext is the tuple [value, filename?, mediaType?, meta?]. Laboratory
// reading: the shortest array that holds every present element, absent ones before the last
// present one written as null (ENV §3 encodes an absent array element as null).
export function privateTuple(field) {
  const tuple = [fromJson(field.value)]
  const rest = ['filename', 'mediaType', 'meta']
  const last = Math.max(-1, ...rest.map((key, i) => (key in field ? i : -1)))
  for (let i = 0; i <= last; i++) tuple.push(rest[i] in field ? fromJson(field[rest[i]]) : null)
  return tuple
}

export function writeRecord(request, hooks = {}) {
  const h = name => hooks[name] ?? id
  checkWriteRequest(request)
  const { writer, record, random } = request
  const keys = split(unhex(writer.rootIkm))
  const { acct, rid } = writer
  const aid = record.aid
  const fields = record.fields.map(field => ({ ...field, n: field.n.normalize('NFC') }))
  const derived = { signing: null, outer: [], fields: {} }

  // ENV §5.1, §6.2, §7: public and audit slots in declared order.
  const slot = field => ('value' in field ? { n: field.n, v: fromJson(field.value) } : { n: field.n, u: true })
  let pu = fields.filter(f => f.sn === 'pu').map(slot)
  let au = fields.filter(f => f.sn === 'au').map(slot)

  // ENV §9, §13 step 4: private slots.
  const fieldParts = {}
  let pr = fields.filter(f => f.sn === 'pr').map(field => {
    if (!('value' in field)) return { n: field.n, u: true }
    const rnd = lookup(random.fields, field.n)
    const plaintext = h('fieldPlaintext')(encode(privateTuple(field)), field.n)
    const compressed = h('fieldCompressed')(compress(plaintext), field.n, plaintext)
    const recipients = []
    let protectedHeader = { enc: 'A256GCM' }
    if (field.cv === true) {
      const secrets = calculateSecrets(plaintext)
      protectedHeader = { enc: 'A256GCM', iter: MIN_ITERATIONS, salt: b64u(secrets.hash) }
      recipients.push({ alg: GCMKW, kek: secrets.cek, kwiv: unhex(rnd.kwiv) })
      fieldParts[field.n] = { secrets }
    }
    const fid = fieldId(acct, rid, aid, field.n)
    const kids = []
    if (field.blind !== true) {
      const self = p256Self(keys.p256Seed, fid)
      kids.push({ who: 'self', kid: hex(self.pub) })
      recipients.push({ alg: ECDH, kid: hex(self.pub), pub: self.pub })
    }
    for (const root of lookup(request.fieldRecipients, field.n) ?? []) {
      const child = p256Theirs(keys.p256Seed, unhex(root), fid)
      kids.push({ who: root, kid: hex(child.pub) })
      recipients.push({ alg: ECDH, kid: hex(child.pub), pub: child.pub })
    }
    let e = 0
    for (const r of recipients) if (r.alg === ECDH) r.epk = unhex(rnd.epk[e++])
    if (e !== rnd.epk.length) fail(`frozen epk count for field ${field.n}`)
    const jwe = h('fieldJwe')(buildJwe({ protectedHeader: h('fieldProtected')(protectedHeader, field.n), plaintext: compressed, cek: unhex(rnd.cek), iv: unhex(rnd.iv), recipients }), field.n)
    derived.fields[field.n] = kids
    fieldParts[field.n] = { ...fieldParts[field.n], plaintext, compressed, jwe, cek: rnd.cek }
    return { n: field.n, jwe }
  })
  ;({ pu, au, pr } = h('slots')({ pu, au, pr }))

  // ENV §6.1, §8.5; KEYS §2.7.1: hdr.pk is the per-record signing key, and the signature kid is its hex.
  const signer = p256Self(keys.p256Seed, signId(acct, rid, aid))
  derived.signing = hex(signer.pub)
  const ctx = { ...(hooks.extra ?? {}), keys, signer, derivedKid: hex(signer.pub), outerSelfKid: hex(p256Self(keys.p256Seed, outerId(acct, rid, aid)).pub) }
  const descriptor = f => ({ n: f.n, sn: f.sn, pl: f.pl, ...(f.cv === true ? { cv: true } : {}) })
  const hdr = h('hdr')({
    aid, ep: writer.ep, f: record.f, mv: record.mv, tm: record.tm,
    fields: fields.map(descriptor),
    pk: signer.pub, pks: 'root', dref: [], ds: false
  }, ctx)

  // ENV §8.2: detached ES256 over the deterministic encoding of {hdr, au, pr}.
  const signedBytes = h('signedBytes')(encode({ hdr, au, pr }), { hdr, au, pr }, ctx)
  const sigKid = h('sigKid')(hex(signer.pub), ctx)
  const protectedB64 = protectedSig(sigKid)
  Object.assign(ctx, { kid: sigKid, signedBytes, protectedB64 })
  const signerKey = h('signerKey')(signer.d, ctx)
  const signature = h('signature')(es256(signerKey, signingInput(protectedB64, signedBytes)), ctx)
  const sigs = h('sigs')({ payload: '', signatures: [{ protected: protectedB64, signature: b64u(signature) }] }, ctx)
  const auditObject = h('audit')({ hdr, sigs, au, pr }, ctx)
  const auditLayer = h('auditBytes')(encode(auditObject), auditObject, ctx)

  // ENV §5.2, §13 steps 9-10: the outer wrap.
  const convergent = fields.some(f => f.sn === 'pr' && f.cv === true)
  const rnd = random.outer
  const recipients = []
  let outerProtected = { enc: 'A256GCM', proto: FORMAT, aid }
  let recordSecrets = null
  if (convergent) {
    recordSecrets = calculateSecrets(auditLayer)
    outerProtected = { enc: 'A256GCM', iter: MIN_ITERATIONS, salt: b64u(recordSecrets.hash), proto: FORMAT, aid }
    recipients.push({ alg: GCMKW, kek: recordSecrets.s1, kwiv: unhex(rnd.kwiv) })
  }
  const protectedAid = h('protectedAid')(aid)
  const oid = outerId(acct, rid, protectedAid)
  const self = p256Self(keys.p256Seed, oid)
  derived.outer.push({ who: 'self', kid: hex(self.pub) })
  recipients.push({ alg: ECDH, kid: hex(self.pub), pub: self.pub })
  for (const root of request.auditRecipients) {
    const child = p256Theirs(keys.p256Seed, unhex(root), oid)
    derived.outer.push({ who: root, kid: hex(child.pub) })
    recipients.push({ alg: ECDH, kid: hex(child.pub), pub: child.pub })
  }
  let e = 0
  for (const r of recipients) if (r.alg === ECDH) r.epk = unhex(rnd.epk[e++])
  if (e !== rnd.epk.length) fail('frozen outer epk count')
  const outer = h('outer')(buildJwe({ protectedHeader: h('outerProtected')(outerProtected), plaintext: auditLayer, cek: unhex(rnd.cek), iv: unhex(rnd.iv), recipients, epkInProtected: hooks.outerEpkInProtected === true }))

  // ENV §2, §13 step 11.
  const envelopeObject = h('envelope')({ proto: FORMAT, pu, outer })
  const envelope = h('bytes')(encode(envelopeObject))
  return { envelope, auditLayer, signedBytes, signature, protectedB64, outer, derived, fieldParts, recordSecrets, keys, hdr, extra: ctx }
}

export const p256Point = text => p256.Point.fromHex(text)
