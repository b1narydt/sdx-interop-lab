<!-- tpnil:provenance-header -->
**TPNIL pinned source text.** SDX Protocol specification v0.1, dated 2026-07-17, revised 2026-09-01; keys, envelope and anchoring ratified 2026-09-01. This file holds the page *The record envelope and field placement*, a normative section ratified on 2026-09-01. Requirement citations use the clause prefix `ENV`.

- Source page: <https://sdxprotocol.org/protocols/data-sharing/v0.1/envelope/>
- Retrieved from: <https://sdxprotocol.org/llms.mdx/protocols/data-sharing/v0.1/envelope.md>, the site's Markdown rendition of the source page
- Retrieved at: 2026-11-11T05:08:32Z
- SHA-256 of the retrieved bytes: `1b5b980ca8eb73277b712257ece838e852a91fad87d3c4f3ef44c8e43018dc73`
- Licence: SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. [Reference copy](../../../../../LICENSES/SDX-Specification-License-1.0.reference.txt)
- Modification: none. The retrieved bytes follow the closing marker of this header unchanged; TPNIL added only this header. Root-relative links in the text resolve against `https://sdxprotocol.org`.

Attribution: SDX Protocol specification, version 0.1 (2026-07-17, revised 2026-09-01). The source page is the canonical publication. This copy retains the SDX licence terms and is excluded from TPNIL's Apache-2.0 grant; see the [third-party notices](../../../../../THIRD_PARTY_NOTICES.md).
<!-- tpnil:upstream-text-follows -->
# The record envelope and field placement (/protocols/data-sharing/v0.1/envelope)



> Normative. Reflects the specification as ratified on 1 September 2026. Version pinning is by date. Where this text and a published test vector disagree, the vector wins and the text is corrected.

## The record envelope [#the-record-envelope]

### Status of this section [#status-of-this-section]

This section specifies the wire format of an SDX record envelope: the byte structure a writer produces, the cryptographic layers it carries, and the procedures a conforming encoder and decoder MUST follow. It is normative.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are to be interpreted as described in RFC 2119.

### 1. Model [#1-model]

An envelope is a three-layer structure. Each layer corresponds to one sensitivity class, and a field's sensitivity determines which layer its data sits in rather than which recipient list it appears on.

| Layer                  | What it holds                                                                                                      | What opens it                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| Outside the outer wrap | Public field slots, in plaintext                                                                                   | Nothing. Any observer of the settlement network reads them. |
| Audit layer            | The header, the signatures, audit field slots in plaintext, and the container of per-field encrypted private slots | The outer wrap                                              |
| Inner layer            | Private field content, each field encrypted under its own recipient list                                           | The outer wrap, then that field's own key                   |

Three parties appear throughout. The **writer** is the node that produces and signs the record. A **recipient** is a party the writer has authorised to open some part of it. An **observer** is any party that can read the settlement network and holds no key at all.

Terminology used below:

* **Sensitivity code**: one of `pu` (public), `au` (audit), `pr` (private), carried on each field descriptor as `sn`. It determines the field's structural position.
* **Placement code**: one of `ch` (in-record), `ov` (overlay), `ex` (external), carried on each field descriptor as `pl`. It determines whether the field's value bytes travel inside the envelope or off it. Placement is specified in the section "Field placement".
* **Deterministic encoding profile**: the canonical CBOR profile every hash, signature and byte comparison in this specification is taken over. Its rules are in section 3.
* **Content-derived secrets**: the optional per-field key material derived from a field's own plaintext, specified in section 4.
* **Convergent property**: the property that a party already holding a plaintext can regenerate the key that was used to encrypt it and confirm the record carries exactly that plaintext. It is opt-in per field and OFF by default.

### 2. Wire structure [#2-wire-structure]

The envelope is a single deterministically encoded CBOR map:

```
Envelope = {
  "proto":  <format identifier>, // the deployment profile's registered value;
                                 // the example profile's is "sdx:record:v1"
  "pu":     [ <PublicSlot>* ],   // plaintext slots for sn="pu" fields
  "outer":  <OuterJWE>           // decrypts to the audit layer
}
```

`proto` carries the **format identifier** registered by the deployment profile the record belongs to. It is a text string, and it lets tooling recognise the envelope format without holding any key, because it sits outside every wrap.

**Every party of one deployment MUST use that deployment's registered identifier byte for byte.** An encoder MUST emit it, and a decoder MUST refuse a record whose `proto` is not the identifier of a profile it is configured for. The identifier is a parameter of the profile rather than a constant of this specification, so a record is recognisable through the published profile rather than through a value fixed here. Where a concrete value appears in this document it is the example profile's `sdx:record:v1`. **That value is illustrative and non-normative**, and no implementation should emit it because it appears here.

`outer` is a JWE in the General JSON Serialization of RFC 7516 §7.2.1, carried as a CBOR map whose members hold the base64url strings that serialisation defines (`protected`, `recipients[]`, `iv`, `ciphertext`, `tag`).

The three structural positions are:

| Sensitivity | Position on the wire                                        | What must be held to reach the content    |
| ----------- | ----------------------------------------------------------- | ----------------------------------------- |
| `pu`        | Outside the outer wrap, in the top-level `pu` array         | Nothing; the value is plaintext           |
| `au`        | Inside the outer wrap, in the audit layer's `au` array      | The outer wrap                            |
| `pr`        | Inside the audit layer, in the `pr` array of per-field JWEs | The outer wrap, then that field's own key |

#### 2.1 The deployment profile [#21-the-deployment-profile]

A **deployment profile** is the published parameter set that a group of interoperating parties agrees on. This specification fixes the structure, the algorithms and the procedures; the profile fixes the values that must match byte for byte between a writer and a reader but that this specification deliberately does not name.

**A deployment MUST fix and publish its profile before its first live write.** The profile MUST at minimum carry:

* the **format identifier** placed in `proto` and in the outer protected header (sections 2 and 5.2);
* the **derivation protocol identifiers**, one per cryptographic purpose, which MUST be distinct from one another (sections 8.5 and 8.6);
* the **key identifier grammar**, meaning the exact segment literals and their order (sections 8.5 and 8.6).

Every one of these is an input to bytes that are permanent once written. A party that joins a deployment later derives against the published profile and reaches the same points; a party that guesses a value derives a key nobody else can match, and on a permanent record that failure is silent and unrecoverable. Publishing before the first write, rather than documenting after it, is what makes the profile the authority rather than a description of whatever the first implementation happened to do.

A deployment profile MAY carry further parameters, and the values this specification does fix are not among them: the algorithm identifiers of section 16, the sensitivity and placement codes, the map keys, the iteration count and the URI scheme allowlist are properties of the format and are not deployment parameters. Note that the deterministic encoding profile of section 3 is a different thing entirely, fixed here and identical across every deployment.

### 3. The deterministic encoding profile [#3-the-deterministic-encoding-profile]

Every byte sequence this specification hashes, signs or compares is produced by one deterministic CBOR profile. Two conforming implementations MUST produce identical bytes for identical values, because a signature is verified by re-encoding rather than by lifting a byte range off the wire (section 8.5).

Encoder rules, all normative:

1. Map keys MUST be sorted by the bytewise ordering of their encoded key bytes, per RFC 8949 §4.2.1. This is not lexicographic ordering of the decoded strings and implementations MUST NOT substitute their language's native string ordering.
2. Integers MUST use the shortest of the 1, 2, 4 and 8 byte argument forms. An integer that needs the 8-byte head MUST be encoded as an integer and MUST NOT be encoded as a binary64 float.
3. The value domain is the integers exactly representable as a 64-bit float, that is the range from -(2^53 - 1) to 2^53 - 1. A value outside that domain MUST be refused at the encoder rather than encoded approximately, because the profile forbids the bignum tags that would be needed to carry it exactly.
4. Tagged items MUST NOT be emitted, and a decoder MUST reject any tagged item it meets.
5. Indefinite-length items MUST NOT be emitted, and a decoder MUST reject them.
6. A set MUST be serialised as an array whose items are sorted by their canonical encodings.
7. A timestamp MUST be serialised as an integer count of milliseconds since the Unix epoch, with no tag.
8. Byte strings MUST use the CBOR byte-string major type without a tag.
9. An absent value MUST be elided from a map. A `null` MUST be preserved and is a distinct value from an absent one.
10. Map sizes MUST use the shortest length form. Float widths MUST be bit-exact.

The behaviour of an absent value differs by position, and three of this specification's rules exist because of it:

| Position                         | An absent value becomes                                                    | Consequence                                                                                                                      |
| -------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| A map member                     | Elided; the key never reaches the wire                                     | A slot written as `{n, v: <absent>}` ships as a bare `{n}`, which section 7.3 rule 1 rejects. Hence the explicit unset marker.   |
| An array element                 | Encoded as `null`                                                          | An absent private value would be indistinguishable from one the caller set to `null`. Hence the marker for private fields too.   |
| A whole value encoded on its own | Preserved as CBOR `undefined` (`0xf7`), distinct from CBOR `null` (`0xf6`) | Externalised plaintext round-trips an absence faithfully in its own bytes and therefore needs no marker, and MUST NOT carry one. |

This asymmetry is a property of the profile. The envelope format adapts to it; the profile is not relaxed to smooth it over, because every hash, signature and state comparison in the system depends on the profile being fixed.

A decoder implementing this profile is semantic rather than strict-canonical: it MUST reject tags and indefinite-length items, and it MAY accept a non-shortest integer head and return the value that head denotes. Rejecting every non-canonical encoding on the read side would re-derive the whole profile at a boundary that does not need it.

### 4. Content-derived secrets [#4-content-derived-secrets]

The derivation is:

```
calculateSecrets(data, iterations = 200000):
  hash      = SHA-256(data)                                        // 32 bytes
  cryptoKey = PBKDF2-HMAC-SHA-256(password = data,
                                  salt     = hash,
                                  c        = iterations,
                                  dkLen    = 64)                   // 512 bits
  s1  = cryptoKey[0 .. 32)
  s2  = cryptoKey[32 .. 64)
  CEK = HMAC-SHA-256(key = s2, message = s1)                       // 32 bytes
  return { s1, s2, CEK, hash, iterations }
```

The salt is the SHA-256 of the data itself, which is what makes the derivation reproducible by any party holding that data.

**The HMAC argument order is load-bearing.** The key is `s2` and the message is `s1`. Reversing them yields 32 deterministic bytes that pass any self-consistent round-trip test and fail every decryption against a conforming envelope. Implementations MUST pin this with a literal test vector rather than with a round trip against their own encoder.

`iterations` MUST be at least 200000. An implementation MUST refuse a smaller value rather than perform a weaker derivation.

**The derivation runs only on request.** It is invoked in exactly two places, both conditional:

* Once per private field whose descriptor declares `cv: true` (section 6.1), over that field's plaintext bytes, producing that field's `{s1, s2, CEK, hash}`.
* Once per record, over the audit-layer bytes, producing the record-level `{s1, hash}` for the outer wrap, when and only when at least one private field declares `cv`. There is no separate record-level opt-in, so a record built entirely of public and audit fields is never convergent.

It MUST NOT be invoked for a public or audit field. Those values are plaintext and derive no key, so `cv` on such a descriptor MUST be rejected rather than ignored.

**Encoding a record whose fields all omit `cv` MUST perform zero PBKDF2 operations.** This is testable and implementations SHOULD assert it by counting calls into the primitive itself rather than into a wrapper around it.

The rationale for making this opt-in is worth stating, because the default is the unusual choice. PBKDF2 exists to stretch a low-entropy secret. The input here is a document plaintext rather than a password, so the stretching buys little, and at 200000 iterations over a 512-bit output it costs 400000 HMAC-SHA-256 operations per call, once per private field and once per envelope, on every write. Nothing on the ordinary read path consumes the result, because readers reach content through the recipient slots of section 8.6, which are unconditional. Making it opt-in removes that cost from writers who never wanted the convergent property, and removes the confirmation oracle of section 15.3 from their records as a side effect. The iteration count is unchanged for anyone who does want it.

### 5. Public slots and the outer layer [#5-public-slots-and-the-outer-layer]

#### 5.1 Public slots [#51-public-slots]

For each field whose descriptor carries `sn: "pu"`, the encoder emits one entry in the top-level `pu` array:

```
PublicSlot (in-record, pl = "ch"):
  { "n": <fieldName>, "v": <value> }

PublicSlot (declared but unset, pl = "ch" only):
  { "n": <fieldName>, "u": true }

PublicSlot (externalised, pl = "ov" or "ex"):
  { "n": <fieldName>, "im": { "sha": <32-byte string>, "u": <text>, "sz": <uint> } }
```

The value of an in-record public slot is the field's typed value, encoded under the deterministic profile as part of the envelope. The value of an externalised public slot is the off-envelope byte sequence whose SHA-256 matches `im.sha`.

Public fields are plaintext to any observer. Writers MUST use `pu` only for values that are safe to publish: operation-type tags, already-public content hashes, directory-style index keys. The unset marker carries additional weight here, because public slots sit outside the signature (section 8.4): a decoder that read a bare `{n}` as an absence would accept a public slot an intermediary had stripped of its value as though the omission were the author's intent, with nothing to detect the edit.

#### 5.2 The outer wrap [#52-the-outer-wrap]

The outer JWE encrypts the audit-layer bytes under `A256GCM`.

Its protected header always carries three members:

* `enc`, which MUST be `A256GCM`.
* `proto`, which MUST be the deployment profile's format identifier, the same value the top-level `proto` member carries.
* `aid`, which MUST equal the record identifier carried in the audit-layer header.

On a convergent record it additionally carries `iter` and `salt`, and only then:

* `iter`, the iteration count of the record-level derivation.
* `salt`, the SHA-256 of the audit-layer plaintext, which is that derivation's salt.

`iter` and `salt` describe the convergent derivation and MUST travel with it. This header is base64url-readable with no key at all, so `salt` is a hash of the audit-layer plaintext handed to every observer. Emitting those members without the corresponding recipient would pay the whole privacy cost of convergence and deliver none of the capability, so an encoder MUST emit both or neither, together with the recipient they describe.

The wrap carries recipients of two kinds.

**The convergent recipient**, present if and only if the record is convergent. Its algorithm is `A256GCMKW` and its key is the record-level `s1`. Any party holding the audit-layer plaintext can regenerate that key, which is what the convergent property means at this layer. Its key identifier is a serialisation detail rather than an identity: this specification does not pin it, and a decoder MUST NOT offer it to a key resolver as a recipient identity.

**Identity recipients**, wrapped under `ECDH-ES+A256KW`, one per authorised audit-tier party. Each carries an unprotected header of `{ "alg": "ECDH-ES+A256KW", "kid": <hex of the recipient point> }`. Section 8.6 pins how the point is obtained.

Two rules bound the recipient list.

**The outer wrap MUST carry at least one recipient.** A record that is neither convergent nor addressed to any audit recipient would carry an audit layer no key could ever open, permanently and silently. An encoder MUST refuse that input rather than emit it.

**The writer self-recipient is REQUIRED on the outer wrap and stays required in every case.** It is the access path that lets a writer that has lost its local state ingest its own records back from the settlement network and reach the header, the signatures and every audit field. Field-level blindness (section 9) is scoped to the inner layer and never removes this slot. Writers and encoders MUST NOT offer a switch that removes it. An envelope without it is not a blind field, it is an unrecoverable record, and it would take the whole audit trail of a record down in order to protect one field.

Implementations should note where each obligation can actually be enforced. The at-least-one-recipient guard is decidable inside the encoder, because it depends only on the recipient list and the convergence flag. The presence of the self-recipient specifically is not, because the encoder consumes a uniform list of already-normalised recipients and cannot tell which entry is the self slot. That obligation therefore binds the layer that assembles the recipient list, and any write path that assembles one owes the same unconditional inclusion. Nothing below that layer will catch its absence.

#### 5.3 Why the record identifier is in the protected header [#53-why-the-record-identifier-is-in-the-protected-header]

A reader restarting from raw settlement bytes plus its own root key material has no audit-layer plaintext, so it cannot regenerate the record-level `s1`. Its only access path is its own identity recipient slot, whose key is derived under a key identifier that includes the record identifier. Surfacing `aid` in the outer protected header gives the reader that input before any decryption succeeds, so it can compute one candidate private key in constant time and hand it to the JWE decryption step.

The alternative of putting the input on each recipient's unprotected header was rejected: the protected header is exposed as a single decoded object, whereas recipient headers are walked per slot, so that alternative would force one candidate derivation per slot and leak slot-walking timing.

The privacy cost is bounded. `aid` is a per-record identifier in ULID grammar and is opaque on its own. It does not enable recovery of any party's identity, and it is covered by the AES-GCM authentication tag, so tampering with it breaks decryption rather than misdirecting it.

Two rules follow:

* Every conforming encoder MUST set `aid` in the outer protected header to the record identifier in the audit-layer header.
* A decoder MUST reject an envelope whose protected-header `aid` does not match the header's own `aid` after the outer decrypt, and MUST reject one whose protected-header `aid` is missing or is not a text string. This is a consistency check against an adversarial encoder splicing two records' material, and it is defence in depth rather than a precondition of the decrypt.

### 6. The audit layer [#6-the-audit-layer]

The audit layer is the deterministic encoding of:

```
AuditLayer = {
  "hdr":  <Header>,
  "sigs": <Signatures>,
  "au":   [ <AuditSlot>* ],
  "pr":   [ <PrivateSlot>* ]
}
```

A decoder MUST reject an audit layer carrying any top-level member outside `{hdr, sigs, au, pr}`. This is defence in depth against an encoder splicing content outside signature coverage. Unknown members nested more deeply are permitted, and that permission is deliberate: it is what lets a decoder written before a descriptor member existed still read records that carry it.

#### 6.1 The header [#61-the-header]

```
Header = {
  "aid":        <text>,                // record identifier, ULID grammar
  "ep":         <uint>,                // key epoch
  "f":          <text>,                // operation name
  "mv":         <uint>,                // operation version
  "tm":         <uint>,                // writer's time, ms since the Unix epoch
  "fields":     [ <FieldDescriptor>+ ],// one per field, in declared order
  "pk":         <33-byte string>,      // signer public key, SEC1 compressed
  "pks":        "root" | "delegate",   // signer scope
  "dref":       [ <16-byte string>* ], // delegation chain; length 0 or 1 in this version
  "ds":         <bool>,                // dual-signed, set on key rotation only
  "refs":       [ <ReadRef>* ]?,       // optional cross-domain read references
  "responseTo": [ <ResponseRef>* ]?    // optional handoff consumption
}

FieldDescriptor = {
  "n":  <text>,                        // field name, NFC-normalised
  "sn": "pu" | "au" | "pr",            // sensitivity
  "pl": "ch" | "ov" | "ex",            // placement
  "cv": true                           // OPTIONAL convergent opt-in
}
```

A decoder MUST reject `pks` outside `{root, delegate}` and `pl` outside `{ch, ov, ex}`.

**Field names MUST be globally unique across all sensitivities.** A single field name is one positional argument slot regardless of which layer the field sits in, and both the encoder's per-name aggregation and the decoder's per-name lookup tables would silently overwrite same-name entries from different sensitivities, mis-aligning external byte windows to fields and corrupting the reconstructed argument list. An encoder MUST reject a duplicate name at write time and a decoder MUST reject one at the descriptor-to-slot cross-check.

The whole header sits inside the outer wrap. This is the metadata-privacy guarantee: an observer sees `proto`, the public slots and `aid`, and learns nothing about the operation name, the field set, the delegation chain or anything else.

**The `cv` convergent opt-in.** A field's descriptor is the one place a field's properties are declared, so the opt-in is declared there and nowhere else. Absent means off. The rules are:

1. `cv` MUST be either absent or exactly the boolean `true`. `cv: false` MUST be rejected by encoders and decoders alike. Absent is the only spelling of "off", so one meaning has exactly one encoding and two byte-different headers cannot mean the same thing.
2. `cv` is valid only on `sn: "pr"`. On a public or audit descriptor it MUST be rejected rather than ignored, because such a value derives no key and a marker there would let an author believe a public field carried a protection it never had.
3. Both rules MUST be enforced at the encoder as well as at the decoder. An encoder that accepts a malformed `cv` signs and permanently anchors a record its own decoder will reject forever.
4. **Dispatch on key presence, not on the value being defined.** Absent and present-but-undefined are different facts. CBOR can carry an explicit `undefined`, which a decoder may materialise as a present member holding an undefined value, and a gate that tests only for definedness reads that as never-declared and lets a member through a grammar meant to be closed. Implementations MUST test for the member's presence and then require its value to be exactly `true`. The same applies at every boundary where a descriptor can arrive untyped.
5. **A `cv: true` declaration MUST be backed at both layers it commits.** `cv` rides inside the signed bytes, so it is a signed claim that this field's key can be regenerated from its plaintext, and that the record-level `s1` can be regenerated from the audit-layer bytes. A decoder MUST reject an envelope whose descriptor declares `cv: true` unless the matching private slot carries both the `A256GCMKW` convergent recipient and the `iter` and `salt` protected-header members; and, whenever any signed descriptor declares `cv: true`, unless the outer wrap satisfies the same conjunctive test. The test is conjunctive, not disjunctive: a slot carrying one half of the material MUST be rejected.
6. **The test is presence of usable material, not cryptographic proof.** A decoder MUST NOT be required to regenerate the key and confirm that it opens the recipient. That is circular at decode time, because regenerating the key needs the very plaintext the decoder is trying to obtain, and it would put the 200000-iteration derivation on the read path. Proving that a record holds particular content is a verifier capability exercised by a party that already holds the content, and it is out of scope for decoding. Presence nonetheless means presence of material: `iter` MUST be an integer no smaller than 200000, and `salt` MUST be present and non-empty. A bare definedness test is not sufficient and MUST NOT be implemented, because it accepts a slot declaring a zero iteration count and an empty salt, which describes no derivation at all. The serialised shape of `salt` is deliberately not constrained here; it is a SHA-256 output whose JOSE representation is an encoding detail.
7. **Both checks MUST run after signature verification.** `cv` is only the writer's claim once the signature covering it holds, so a header-only read that stops short of verification has no verified claim to hold anything to and MUST NOT apply these rules.
8. **The check is one-directional and MUST stay so at both layers.** A slot or an outer wrap carrying convergent material without any `cv` descriptor is exactly what every record written under the previous format generation looks like, and those MUST continue to decode. A symmetric check would break the wire history this rule exists to protect.
9. A declared-but-unset slot is exempt. It has no plaintext and therefore no ciphertext, so there is no material for the claim to be backed by.

#### 6.2 Audit slots [#62-audit-slots]

For each field whose descriptor carries `sn: "au"`, the encoder emits one entry in the audit layer's `au` array, in the same three shapes as a public slot:

```
AuditSlot (in-record):        { "n": <fieldName>, "v": <value> }
AuditSlot (unset):            { "n": <fieldName>, "u": true }
AuditSlot (externalised):     { "n": <fieldName>, "im": { "sha", "u", "sz" } }
```

The wire shape is identical to a public slot. What differs is structural position: audit slots sit inside the outer wrap, so any party that can open that wrap reads them in plaintext, and no observer can.

### 7. Declared but unset [#7-declared-but-unset]

A field may be declared in `hdr.fields` and carry no value. This is what an operation's optional argument looks like when the caller omits it. The descriptor is still emitted, because the argument list is reconstructed as one element per descriptor in declared order, so dropping the descriptor would drop an argument position and silently shift every later argument one place.

An unset in-record field MUST be written as `{ "n": <fieldName>, "u": true }`, and a decoder MUST surface it as a field present in declared order carrying no value.

Four rules make this safe, and all four are normative.

1. **The marker MUST be explicit.** A slot carrying neither a value nor the marker MUST be rejected. Absence is also what a truncated, stripped or forged slot looks like, and public slots are not covered by the signature, so a decoder that read a bare `{n}` as unset would silently accept a stripped public field as a legitimate absence. Being unset must be stated, not inferred from what is missing.
2. **The marker MUST NOT accompany a value.** A slot carrying `u` alongside `v`, `jwe`, `im` or `je` MUST be rejected. Two readings of one slot force the decoder to choose, and the wrong choice discards a value that is actually present.
3. **`u` MUST be exactly `true`, and the marker is in-record only.** Any other value for `u`, or the marker on a descriptor whose placement is `ov` or `ex`, MUST be rejected. An externalised descriptor promises off-envelope bytes and a manifest to anchor them, and there is nothing to anchor for an absent value.
4. **The marker slot's member set is closed: exactly `n` and `u`.** A slot carrying the marker together with any other member MUST be rejected, including members this specification does not name. This is stated as a closed set rather than as a longer forbidden list, and the distinction is the point: a forbidden list only ever rejects the members someone thought to enumerate, so a slot carrying the marker plus one unrecognised member would satisfy rules 1 to 3 and decode as a legitimate absence. A decoder that ignores what it does not recognise cannot later be tightened without breaking whatever came to rely on being ignored, and these records are permanent. Adding a member to the marker slot therefore requires a deliberate amendment, which is the intended cost. Both halves of "exactly `n` and `u`" bind: no member outside the set, and both members present.

**Which members the rules are evaluated against is not the same for all of them.** On the wire the question does not arise, because the deterministic profile produces a plain map with no inherited members. It arises wherever an implementation publishes a marker predicate for consumers to call on values they construct themselves, or accepts a caller-supplied slot at an exported boundary. Rules 1, 3 and 4 MUST be evaluated against the slot's own members only, and rule 2 against own and inherited members alike. The asymmetry is deliberate. Ownership is what makes the marker a statement, so a slot whose `u` is inherited has own members of exactly `{n}`, which is the bare shape rule 1 refuses. Rule 2 asks a different question, namely whether a readable value is present, and an inherited ciphertext member is still ciphertext a consumer can read, so declaring that slot absent would discard a real value.

#### 7.1 Unset private fields [#71-unset-private-fields]

A declared-but-unset private field uses the same marker under the same four rules. One shape serves both in-record placements: a public and a private field state an absence identically, and what differs is only the value they would otherwise carry.

The marker is required here rather than merely convenient. A private field's value is encoded inside an array (section 9), and the deterministic profile encodes an absent array element as `null`. Without the marker, an omitted optional would encrypt cleanly, decode cleanly and yield `null`, so a value the caller never supplied would be permanently indistinguishable from one they deliberately set to `null`, with no error raised anywhere.

An unset private field carries no ciphertext. A decoder MUST NOT consult the per-field key resolver for it, and MUST NOT surface it as redacted. Redaction means that a value exists and the reader is not authorised to read it, which would be a false claim about a field that has no value. Absence also means the whole tuple is absent: no filename, media type or metadata survives an unset field, and an encoder MUST reject an unset field that supplies any of them rather than silently dropping data the caller gave it.

**An externalised private field cannot represent absence, and encoders MUST refuse the combination.** Such a field has no bytes to externalise and therefore no manifest to anchor, and the marker is in-record only. Rather than inventing a third representation for a case with no demonstrated need, or anchoring a `null` in its place, an encoder MUST reject at write time with a diagnostic naming both the field and the placement. This is a deliberate limitation: on a permanent record a refusal costs an operator an error message, whereas a wrong value costs a permanent record. An application that needs an optional private field declares it in-record.

### 8. Private slots and signatures [#8-private-slots-and-signatures]

#### 8.1 Private slot shapes [#81-private-slot-shapes]

For each field whose descriptor carries `sn: "pr"`, the encoder emits one entry in the audit layer's `pr` array:

```
PrivateSlot (in-record, pl = "ch"):
  { "n": <fieldName>, "jwe": <PerFieldJWE> }

PrivateSlot (declared but unset, pl = "ch" only):
  { "n": <fieldName>, "u": true }

PrivateSlot (externalised, pl = "ov" or "ex"):
  { "n": <fieldName>,
    "je": <JWE with the ciphertext member removed>,
    "im": { "sha": <32-byte string>, "u": <text>, "sz": <uint> } }
```

Only the ciphertext ever leaves the envelope. The JOSE wrappers, meaning the protected header, the recipient list with each wrapped key, the initialisation vector and the authentication tag, stay inline in every placement. There is therefore no placement in which a field recipient reaches content without audit-layer access.

A slot mixing in-record and external members, for example one carrying both `v` and `im`, MUST be rejected before any fetch or decryption. Duplicate slot names within one array MUST be rejected. A slot present in an array but not named in `hdr.fields` MUST be rejected.

#### 8.2 Signature construction [#82-signature-construction]

Signatures cover the audit layer minus the signatures themselves.

**Detached-payload mode is normative**, per RFC 7515 Appendix F. The carried `payload` member MUST be the empty string. The signature is still computed over the full canonical bytes; only the carried copy is dropped from the wire.

```
signedBytes = deterministicEncode({ hdr, au, pr })      // everything except sigs
payloadB64  = base64url(signedBytes)                    // signing input only, not carried

for each signer:
  protectedB64 = base64url(utf8(JSON({ "alg": "ES256", "kid": <signer kid> })))
  signingInput = utf8(protectedB64 || "." || payloadB64)
  signature    = ES256(signingInput)                    // 64-byte P1363, not DER
  emit { "protected": protectedB64, "signature": base64url(signature) }

sigs = { "payload": "", "signatures": [ ... ] }
```

A record that rotates key material carries a second signature and sets `ds` to true: the primary signer is derived from the previous root identity at the header's epoch, and the rotation signer from the new root identity at the new epoch.

The empty-string sentinel is chosen over deleting the member, which RFC 7515 Appendix F describes non-normatively as an alternative. Keeping the member present preserves the serialised shape across all encoders so that structural type guards stay stable, gives the decoder a single observable invariant to assert rather than a presence-versus-absence test, and costs a single empty-string encoding against the full base64url payload that detaching removes.

#### 8.3 Signature verification [#83-signature-verification]

A reader verifies by:

1. Reconstructing `signedBytes` as the deterministic encoding of `{hdr, au, pr}` taken from the decoded audit layer, which is the authenticated source because the whole audit layer is covered by the outer wrap's authentication tag.
2. **Asserting that the carried payload is the empty string.** Any other value MUST be rejected as a signature failure. This includes the correctly reconstructed attached-payload value, which an earlier generation of this format carried. The check is a guard against an encoder reintroducing attached-payload semantics, and loosening it to accept the old value would silently re-admit records this format rejects.
3. Feeding the locally computed base64url of `signedBytes` to the verifier as detached content.

**Reconstruction is sensitive to the version of the encoding profile.** Step 1 is a re-encode, not a byte range lifted off the wire, so verification depends on the reader reproducing the profile the writer used. Any change to the profile therefore reaches back through every record ever written.

One such change has occurred: integers requiring the 8-byte head were previously encoded as a binary64 float, contradicting rule 2 of section 3. Every envelope carries a millisecond timestamp above 2^32, so every record written before that fix was signed over the superseded shape.

Step 1 is therefore a candidate list rather than a single reconstruction, ordered current-shape-first:

1. Rebuild `{hdr, au, pr}` under the current profile.
2. If no signature verifies against it, rebuild once under the superseded integer shape.
3. If no signature verifies under any candidate, reject. **Failing closed is normative**; the candidate list is not an escape hatch.

Every candidate is derived from the same decoded values, so this widens which of the reader's own serialisations may match and never what content is accepted. There is no second input for an attacker to supply, and the authentication-tag coverage of the audit layer is untouched. Implementations SHOULD build the superseded candidate lazily, because the audit layer is the most expensive object in the envelope to serialise and every record written since the fix verifies on the first candidate.

The obligation is permanent. Records written under the superseded shape are immutable, so a reader that drops the second candidate silently stops verifying its own history.

A decoder MUST reject an empty signature list.

#### 8.4 What the signature does not cover [#84-what-the-signature-does-not-cover]

Signatures cover `{hdr, au, pr}`, which is all of the audit-layer content except the signatures themselves. **Public slots are not covered**, because they sit outside the audit layer. A malicious relayer could therefore alter a public field after the fact. The mitigation is that public fields are public anyway, so alteration is detectable by any party that compares against its own copy. Writers who need signed coverage of a public value MAY duplicate it, or a hash of it, as an audit field, so that the signature covers the commitment.

#### 8.5 The signing key identifier [#85-the-signing-key-identifier]

The `kid` in each signature's protected header MUST be the SEC1-compressed hex of the per-record signing public key, which is 33 bytes and therefore 66 hex characters. That key is derived from the signer's root identity under an open, published key-derivation standard, with:

| Input               | Value                                                                |
| ------------------- | -------------------------------------------------------------------- |
| Protocol identifier | The registered signing protocol identifier for this profile          |
| Key identifier      | `account/<account-id>/<writer-scope>/<writer-id>/record/<record-id>` |
| Counterparty        | The signer's own identity                                            |
| Direction           | Sender-side, deriving the signer's own key                           |

The protocol identifier and the segment literals of the key identifier are profile parameters, published per section 2.1. The shape above is normative: the identifier is record-scoped, and the record identifier is its final segment.

The properties that matter:

* **Privacy from observers.** Key identifiers live inside the outer wrap, so an observer without audit-tier access cannot read them at all. Even with audit-tier access, every record's identifier is a different derived value, and correlating them across records requires recomputing the derivation, which requires the root public key.
* **Verification by a root-holder.** A verifier re-derives the expected per-record signing public key from the root and the same three inputs, and compares hex. A match proves the record was signed by a key whose only legitimate producer is the root-holder.
* **Third-party verification is out of scope by design in this version.** Deriving against the signer's own identity keeps identity-binding verification bounded to root-holders, matching the posture of the settlement-side locking key. Deriving against a wildcard counterparty would extend verification to anyone holding the signer's root public key, which is a stronger property with a wider key-identifier exposure; it is a candidate for a later version and would need to move in lockstep with the settlement-side recipe.
* A writer-chosen opaque identifier is not permitted, because it would force verifiers into a lookup with no canonical recipe and defeat the per-record determinism that admission-time identity checking depends on.

#### 8.6 Recipient key identifiers [#86-recipient-key-identifiers]

The `kid` in each `ECDH-ES+A256KW` recipient slot, on the outer wrap and on each per-field JWE alike, MUST be the SEC1-compressed hex of a per-record derived child public key, and the public key passed to the JWE implementation MUST be that same point.

This section governs identity slots only. The convergent `A256GCMKW` slot's identifier is deliberately not pinned, because that slot is opened by possession of the convergent inputs and never by identifier membership.

| Input               | Outer recipient                                                               | Per-field recipient                           |
| ------------------- | ----------------------------------------------------------------------------- | --------------------------------------------- |
| Protocol identifier | The registered encryption protocol identifier                                 | The same                                      |
| Key identifier      | `account/<account-id>/<writer-scope>/<writer-id>/record/<record-id>`          | The same, with `/field/<field-name>` appended |
| Counterparty        | The writer itself, for the self-recipient, or the recipient's root public key | The same options                              |
| Direction           | Sender-side                                                                   | Sender-side                                   |

As in section 8.5, the protocol identifier and the key identifier's segment literals are profile parameters. What is normative here is the shape: the per-field identifier MUST be the record-scoped one with the field name appended, so that two fields of one record derive to different points.

Both sides of the exchange derive a matching pair: the writer derives the child public key and puts its hex on the wire, and the recipient derives the matching child private key from its own root and the same three inputs. The JWE decryption step walks the recipient slots and finds the match, so no identifier lookup is required to decrypt.

**The signing and encryption protocol identifiers MUST be distinct.** A key derived for ECDSA and a key derived for ECDH are two child trees rooted in the same identity, and reusing one identifier across both primitives is cryptographic key reuse across primitives.

All protocol identifiers MUST be exported as named constants by a conforming implementation, and writers, readers, tests and test vectors MUST import them rather than repeat the literal string. A single source of truth is what keeps two call sites from drifting.

The privacy properties this recipe delivers:

* **Per-record unlinkability against observers.** The identifier is derived by an HMAC over an ECDH shared secret, so computing it requires one of the two private keys. An observer holding only the root public keys of various parties cannot compute the shared secret, cannot invert the HMAC and cannot brute-force a 256-bit scalar. Subtracting any candidate root from the identifier leaves a point for an unguessable scalar, and solving that is roughly 2^128 work on P-256. An observer therefore cannot link an identifier to a root, nor correlate records by recipient identity.
* **Per-pair, per-record unlinkability.** The key identifier embeds the record identifier, so the same sender-to-recipient pair produces a fresh child on every record. Different pairs produce independent children on the same record, because the shared secret is pair-specific. Being a recipient on one record therefore reveals nothing about another record's recipient set, and holding one recipient's private key lets you compute identifiers for records addressed to that recipient and tells you nothing about records addressed to anyone else.
* **Recipient-side and sender-side computation.** A recipient can compute the expected identifier from its own private key and the sender's root, and MAY do so after decrypting as a defence-in-depth check. A sender can always compute each recipient identifier before encrypting, needing nothing beyond the recipient's root and the record metadata.
* **The self-recipient case.** When the counterparty is the writer itself, the exchange degenerates to a value only the root-holder can compute. The resulting child is distinct from the signing key, because the protocol identifier differs, and distinct per record, because the key identifier differs.

#### 8.7 One-time recipient keys held by parties with no registered identity [#87-one-time-recipient-keys-held-by-parties-with-no-registered-identity]

The recipe above presumes a recipient who holds a registered root identity and can re-derive against it. A party holding a single key bound to one artefact rather than to a registered identity holds no root and never registers one, so there is nothing for the sender to derive against. A physical token carrying a keypair generated at the moment it is issued is the case this exists for.

**A recipient key MAY therefore be a one-time P-256 public key used raw, on one explicit condition: it MUST NEVER be used as a recipient on a second record.** The condition is normative. It is not advice, and an implementation that reuses such a key has not taken this option, it has broken the recipe.

**Why the condition carries the property the derivation would have carried.** The identifier on the wire is the hex of the recipient point, whatever its provenance. For a derived child the point is a function of the per-record key identifier, so the same pair yields a fresh, uncorrelatable identifier on every record. A raw key gets no such freshness from derivation, so reusing it across two records puts the identical 66 hex characters on both, and correlating those two records to one holder then needs no private key at all, only the ability to see both identifiers. Per-record key freshness restores exactly that property from the other side: one key, one record, so no two records ever share an identifier.

**Who can see a repeat depends on which layer the slot sits at.** A raw key used as an outer recipient has its identifier in the outer JWE header, which is readable by any observer with no key and no privilege. A raw key used only as a per-field recipient has its identifier inside the audit layer, so a repeat is correlatable by audit-tier holders rather than by the public. The condition is normative in every placement and is not softened by the narrower audience: even the audit-tier-only case hands a linkable identifier to precisely the tier best positioned to correlate one holder's records. What changes between placements is the blast radius, not the obligation.

**What per-record freshness does not restore.** Never-reuse closes correlation between records. It does not close the link between a record and the key's holder, and derivation did close that one. A derived identifier is a point nobody outside the pair can compute, so seeing a recipient's root elsewhere tells an observer nothing about which records are theirs. A raw identifier is the recipient's own public key verbatim, so where that keypair has any other use, a party who has seen it used out of band can simply compare 66 hex characters and find the record. Where the raw key is also an outer recipient, that comparison is available to any observer. **The consequence is normative rather than advisory**: a deployment whose artefact key has any use outside this recipient slot MUST treat the resulting record-to-holder link as public where the slot is an outer one, and MUST NOT rely on the never-reuse condition to prevent it. Mitigating it means a distinct keypair per purpose, which is a deployment obligation this specification cannot check.

**What this does not relax:**

* The **writer self-recipient**, wherever it appears, MUST still be derived under the recipe of section 8.6. It is a registered identity by definition.
* An **external recipient who does hold a registered root** MUST still be derived against that root. This option is available only where no root exists, never as an alternative for parties who have one.
* The **wire shape is unchanged**: still one `ECDH-ES+A256KW` slot, still the hex of the recipient point as the identifier, still the same algorithms. Encoders and decoders need no new branch, and no decoder can or should distinguish the two provenances from the record alone.
* The **consistency check on the record identifier, the signatures and the outer authentication tag** are untouched. A raw recipient changes who can open a slot and changes nothing about integrity.

**What validates a raw recipient key.** This is the first recipient point that can arrive from outside the platform's own key hierarchy, so the validation owed to it is stated rather than assumed. A raw recipient key MUST be validated as a canonical SEC1-compressed point on the P-256 curve, and a recipient entry that declares both a root identity and a raw key, or neither, MUST be rejected. Both checks MUST run at the write boundary and before the key becomes a JWE recipient. The both-present case would otherwise resolve to an unstated precedence that no caller asked for; the neither-present case would wrap an undefined value as a public key and put its rendering on a permanent record. A length-and-shape check alone is not sufficient: a raw one-time key is 33 compressed bytes exactly as a root key is, so a branded type built on length cannot separate them, and a write path that derived against a raw key would produce a slot its intended holder can never open, silently and permanently.

**A consequence worth recording.** A raw artefact key cannot be re-derived by anyone, including its holder. The holder retains the key or loses access permanently. That is a deliberate property where this option is used, and a data-loss bug anywhere else, which is the second reason the never-reuse condition is paired with a narrow authorised use rather than offered generally.

### 9. Per-field encryption [#9-per-field-encryption]

Each private field is independently encrypted. A field whose descriptor declares `cv` is additionally keyed by content-derived secrets; a field that declares nothing is keyed by its recipients alone.

```
// The at-least-one-recipient guard runs FIRST, before any expensive work.
if (cv_i ? 1 : 0) + (selfRecipient_i ? 1 : 0) + count(externalRecipients_i) == 0:
    REJECT

fieldPlaintext = deterministicEncode([ value, filename?, mediaType?, meta? ])
compressed     = LZMA(fieldPlaintext, level = 9, endMarker = disabled)

jwe = JWE.GeneralEncrypt(compressed)

if cv_i:
    { CEK, hash } = calculateSecrets(fieldPlaintext, 200000)
    jwe.protectedHeader = { "enc": "A256GCM", "iter": 200000, "salt": hash }
    jwe.addRecipient(CEK, { "alg": "A256GCMKW", "kid": <unpinned> })
else:
    jwe.protectedHeader = { "enc": "A256GCM" }

if not blind_i:
    jwe.addRecipient(selfChild_i, { "alg": "ECDH-ES+A256KW",
                                    "kid": hex(selfChild_i) })

for each external recipient r:
    // exactly one of a registered root or a raw one-time key; see section 8.7
    point = r.root ? deriveChild(fieldScopedKeyId, r.root) : r.rawOneTimeKey
    jwe.addRecipient(point, { "alg": "ECDH-ES+A256KW", "kid": hex(point) })

perFieldJWE = jwe.encrypt()
```

Notes on the ordering, which is normative:

* The recipient guard runs before the canonical encode and before compression, because it depends only on the descriptor and the recipient list, and compression at level 9 is the single most expensive step on this path. Behind the compression, an already-doomed encode pays for compression first.
* The self-recipient is prepended before any external recipients, so that a root-holding reader resolves it first.
* Compression is LZMA at level 9 with the end-of-stream marker disabled. Both settings are part of the byte definition and MUST NOT be varied.

Properties:

* The per-field key is `HMAC-SHA-256(key = s2, message = s1)` over that field's own plaintext, exactly as the record-level derivation is over the audit layer's.
* **Convergent when requested.** A field declaring `cv: true` keeps the property that any party holding its plaintext can regenerate the key and verify the slot decrypts to that known plaintext. A field that does not declare it has no convergent slot and the property does not hold for it.
* **Every private slot MUST carry at least one recipient.** A field with no convergent slot, no self-recipient and no external recipients encrypts cleanly into a JWE nobody could ever open, permanently. Encoders MUST refuse that input at write time rather than emit it.
* **Recipient lists are per field.** A recipient wrapped into one field's JWE but not another's can decrypt the first and not the second, while still reading every audit field and every public field.

#### 9.1 Writer-blind fields [#91-writer-blind-fields]

**A private field MAY be declared writer-blind, in which case its recipient list is external-only: the writer self-recipient is omitted and no writer slot exists on that field, ever.** The class is defined by that recipient-list shape and by nothing else. It is not specific to any domain, any field type or any category of reader.

On a record carrying such a field:

* the **outer** writer self-recipient is unchanged and still required, so the header, the signatures, every audit field and the whole audit tier stay reachable by the writer;
* **every other private field** keeps the default self-recipient;
* the field's own recipient list carries the external reader or readers alone, commonly a single one-time artefact key under section 8.7.

**A blind field's reader holds a slot on both layers, which is the ordinary full-tier shape rather than anything this class introduces.** Full access to a field has always meant audit-tier access plus that field's own slot, because the per-field wrapped keys ride inside the outer wrap for every placement. So the write shape is: outer wrap carries the writer plus the field's external reader, and the blind field itself carries that reader alone. The audit-tier visibility that comes with the reader's outer slot is inherent to the design and is not a leak this class opens.

**Read access is possession of the key, and this specification means that literally.** Where the external recipient is a key on a physical token, holding the token is being authorised. There is no session, no login, no grant record to consult and no revocation event. Re-reading later is the same key presented again, not a new grant. A holder who destroys or loses the token has destroyed their own access, permanently.

**Possession is the read authorisation, which is a different question from whether a service will hand you the bytes.** Two gates sit over two different things, and neither weakens the other:

* **Read authorisation is cryptographic, and this specification owns it.** It is settled by key possession alone, it is unconditional, and it lasts until the key is destroyed. A holder who obtained the ciphertext once can re-read it forever, offline, with nobody's further permission.
* **Transport authorisation belongs to whichever endpoint hands the ciphertext out, and this specification does not own it.** A node that chooses to serve a blind field's ciphertext over its own interface decides for itself who may ask it for those bytes and on what evidence.

A transport gate cannot grant read access, because the bytes it serves are worthless without a key it does not hold, and it cannot withdraw read access either, because a holder who already has the ciphertext keeps it. A reader whose grant has lapsed has not lost read access in this section's sense; they have lost one node's willingness to re-serve them a copy.

**The price, stated plainly because it is permanent and cannot be retrofitted.** The writer that produced the record cannot recover that field's content. Not from the settlement network, not from its own root key material, not with operator intervention, not by any later amendment. The self-replication tier of section 12 does not hold for a blind field, and the disaster-recovery path that reaches every other field stops at this one. Every consequence follows from that single fact: the writer cannot re-encrypt the field to a new recipient, cannot migrate it across a key rotation, cannot include its content in any projection, and cannot produce it under legal compulsion. **Where this class is used, that loss is the feature**: it makes erasure of the field a property of the cryptography rather than a promise about anyone's conduct, so that destroying the key destroys the content even in copies that escaped deletion. Where it is not the feature, use the default.

The shape is fixed when the record is written and cannot be tightened afterwards. A field written readable by the writer and by an external reader can never become readable by that reader alone, because the first record's ciphertext is already out. An application that intends this class MUST declare it before its first live write, not after a pilot.

**Normative rules.**

1. **The at-least-one-recipient guard still binds.** A blind field MUST carry at least one external recipient. Omitting the self-recipient does not license an empty list, and encoders MUST reject one at write time.
2. **A key resolver that is not a recipient of a field MUST decline it, and MUST NOT attempt a key.** This rule carries four separable obligations.

   **(a) What declining is.** Signalling to the decoder that no key is available for this field, which the decoder surfaces as the redacted marker for that field alone while the rest of the envelope decodes normally. **What a resolver decides with**: the decoder MUST supply the field's identity recipient identifier list to the resolver, because the obligation sits on the resolver and no resolver can discharge it from the protected header, which carries no recipient identity. The identifiers are the slot identifiers of section 8.6, so a resolver compares its own key's compressed public point against them. The convergent slot's identifier MUST NOT appear in that list, because it is deliberately unpinned and a colliding spelling would turn a correct decline into a doomed attempt. A field carried only by a convergent slot therefore presents an empty list, which a membership-deciding resolver correctly declines. Supplying the list discloses nothing new, since audit-tier access already grants the per-field identifier list to every caller that has opened the outer wrap.

   **(b) Why an attempt is not a gentler version of the same thing.** A wrong key reaches the JWE decryption step, which throws, and the decoder converts that into an integrity failure that aborts the **whole** decode. A writer whose resolver optimistically tried its own self-derived child on a blind field would not read a redacted field, it would fail to admit the entire record, and it would look like corruption rather than like the intended blindness.

   **(c) Why the obligation sits on the resolver.** It binds at the point the key is constructed, rather than on the decoder as leniency, because the resolver is the only component that knows which fields its holder is a recipient of.

   **(d) Declining degrades per field on all three placements**, regardless of whether the ciphertext is reachable, because the decoder MUST consult the key resolver before it resolves any external bytes. A declined field reaches the redacted marker without the bytes ever being looked for, so their absence cannot raise. This is what makes the per-field degradation claim of section 12 true rather than aspirational.

   **The check sits as late as it can while still preceding byte resolution, and the ordering within the gate is normative.** Everything that validates the slot still runs first, for a declined field as much as any other: the shape gate on the detached JWE object, the shape gate on the integrity manifest, and the URI scheme allowlist. Only resolution sits behind the authorisation check. Declining any earlier would mean a declined field's malformed manifest was never refused at all, which is a fail-open on exactly the field class this section defines.

   **A decline is only honoured for a structurally valid slot, and that precondition is part of rule 3 rather than decoder leniency.** The redacted marker asserts something, namely that a value exists and this reader may not read it. A slot no reader could open asserts nothing of the kind, so reporting one as withheld would be a false claim. Before returning the marker, a decoder MUST therefore validate everything the decryption step would have validated: the fixed JWE members and their canonical base64url spelling, the wire lengths implied by `A256GCM`, the `enc` value, the RFC 7516 §7.2.1 effective header as the disjoint union of the protected, shared unprotected and per-recipient levels with the union refused outright if any parameter name repeats, and, per recipient, its declared algorithm's own members: an on-curve compressed identity point as the identifier, an on-curve P-256 ephemeral public key carrying no private component, the exact wrapped-key length that algorithm produces, and for `A256GCMKW` the key-wrap initialisation vector and tag read from that union. Each refusal is an integrity refusal. **The precondition binds the decline and not the decode**: a field the resolver authorises meets none of these checks and takes the ordinary route, so the tolerance the decryption step has for a malformed later recipient on a JWE whose earlier one opens is preserved, and so is the unavailable outcome for an absent store. A decoder that validated unconditionally would satisfy the letter of this rule and break that; one that skipped the checks entirely would file corruption as blindness.

   **An in-record private JWE carrying no recipient list at all MUST be refused, not redacted.** A JWE with no recipients yields an empty identifier list, on which every conforming resolver declines, so the field would otherwise surface as withheld when it is in fact structurally corrupt.
3. **A redacted field is a value the reader may not read, never an absent one.** The redacted marker and the declared-but-unset marker are distinct and MUST NOT be conflated: an unset field has no value and MUST NOT reach the key resolver at all, while a blind field has a value this reader is not authorised for. An operation that requires a blind field it cannot read MUST fail as a gated request, not as an integrity failure.
4. **The audit tier still sees the field's structure**: its name, its approximate size, and its recipient identifier list remain visible to anyone who opens the outer wrap. Blindness is over content. The size is visible in both placements but is not the same surface in each: an externalised blind field carries its size explicitly in its manifest, while an in-record one carries no manifest at all and discloses its size as the length of the ciphertext sitting in the slot. Neither placement conceals size.
5. **A blind field MUST NOT declare `cv`.** Two independent reasons, both checkable mechanisms rather than caution. First, the **fingerprint surface**: declaring `cv` puts `salt`, the SHA-256 of the field plaintext, into the per-field protected header, which rides inside the audit layer, so every audit-tier holder can test a guess of the field's content against it. On a field whose entire purpose is that nobody but its external reader can see its content, that hands a plaintext-confirmation oracle to precisely the tier the class exists to exclude. Second, the **reader-count hole**: the guard of rule 1 counts the convergent slot as a recipient, so a field declared blind with `cv` and no external recipient satisfies the guard, encodes cleanly, anchors permanently and is openable by nobody, reachable only by regenerating the key from the very plaintext a reader would be trying to obtain. Rule 1's own requirement of at least one external recipient already forbids that shape normatively, but a recipient count cannot detect it, because it counts without regard to provenance. Rule 5 is what makes the shape refusable at the encoder without a provenance check, by removing the `cv` that lets the count reach one.

How an application declares a field blind is a schema concern outside this section. This section constrains it only by requiring that such a declaration exist somewhere a writer can act on.

### 10. Externalised value bytes [#10-externalised-value-bytes]

For any slot whose placement is `ov` or `ex`, the value bytes travel off the envelope and the envelope carries only the integrity manifest:

* **Public externalised**: `{n, im}` in the top-level array; the off-envelope bytes are the deterministic encoding of the plaintext value.
* **Audit externalised**: `{n, im}` in the audit layer's array; the off-envelope bytes are the deterministic encoding of the plaintext value.
* **Private externalised**: `{n, je, im}` in the audit layer's array; the off-envelope bytes are the JWE's ciphertext member as raw bytes, reinstated into the detached JWE by the reader before decryption.

The section "Field placement" specifies the channels, the manifest, the URI schemes and the failure semantics.

#### 10.1 Manifests on the decode output [#101-manifests-on-the-decode-output]

The canonical per-field manifest lives in the decoded slot arrays, not in the header's descriptor, which carries only the name, the sensitivity, the placement and the optional convergent opt-in. A decoder SHOULD additionally surface the manifests as a flat list, one entry per slot whose placement is `ov` or `ex`, in declared order, with each entry carrying the field name, its sensitivity, its placement and its manifest. Fields placed in-record contribute no entry, and an envelope with no externalised fields yields an empty list.

This is a surfacing rather than a re-derivation: the entries MUST be the same manifest values the decoder read from the slots, with no recomputation, and no member is added to the envelope to carry them. It exists for write-side paths that need to verify caller-supplied off-envelope bytes against the signed manifests before threading them onward.

### 11. The settlement container [#11-the-settlement-container]

The whole envelope encoding goes into a spendable entry on the settlement network whose data field carries the envelope bytes, followed by the per-record locking key.

An observer of the settlement network sees:

* the format identifier in `proto`;
* public field names and their plaintext values;
* the outer protected header, which is base64url-decodable without any key, containing `enc`, `proto` and `aid`, plus `iter` and `salt` only when the record is convergent;
* per-recipient headers on the outer wrap, each carrying the ephemeral public key and the recipient identifier;
* the outer ciphertext, initialisation vector and authentication tag, all opaque.

Everything else, meaning the header with its operation name and field set, the signatures, the audit fields and every private slot, is hidden behind the outer wrap.

On the default path `iter` and `salt` are absent, and that is the point: `salt` is the SHA-256 of the audit-layer plaintext in a header readable with no key, so on a guessable payload it is a confirmation oracle. Declining convergence removes that exposure rather than mitigating it.

The two recipient provenances differ in two respects an observer can act on. A derived identifier is fresh on every record by construction, whereas a raw one is fresh only because section 8.7 forbids its reuse, so reusing a raw key in breach of that condition puts the identical 66 hex characters on two records and makes them correlatable here with no key and no privilege. And a raw identifier is its holder's public key verbatim rather than a point derived from it, so an observer who has seen that key used anywhere else matches it against this header directly.

### 12. Tiered access [#12-tiered-access]

| Tier                            | Requires                                                                                                                                                                                                        | Can read                                                                                                                                                                                                        |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Nothing**                     | Nothing                                                                                                                                                                                                         | `proto`, public field names and values, the outer ciphertext as opaque bytes, the count of recipient slots and each slot's identifier as opaque hex, and `aid` from the outer protected header                  |
| **Audit**                       | Either the private key at the sender or recipient role of an outer identity slot, or the record-level `s1` held out of band, or, only on a convergent record, the audit-layer plaintext, which regenerates `s1` | The Nothing tier, plus the header, the signatures, audit fields in plaintext, and the structure of private slots, meaning their names, their manifests where externalised, and their recipient identifier lists |
| **Full for field X**            | The Audit tier, plus either the private key at the sender or recipient role of field X's identity slot, or field X's per-field key held directly, or, only when field X declares `cv`, field X's plaintext      | The Audit tier plus the decrypted content of field X                                                                                                                                                            |
| **Full for all private fields** | The Audit tier plus recipient standing on every private field                                                                                                                                                   | Everything                                                                                                                                                                                                      |

The audit tier sees the structure of private slots but not their content. This is the same "see the signature, see that the field exists, cannot decrypt it" property the previous format generation provided for the entire content, now applied per field.

**The convergent routes are opt-in and default to absent.** They are conveniences for a party that already holds the plaintext, not grants to anyone who does not, so removing them by default widens nobody's access. The load-bearing paths in every tier are the identity slots, which are unconditional.

**Self-replication tier.** A writer that is on its own outer and per-field recipient lists, which is the default, holds full-tier access through its own root key alone. This is the load-bearing path for replication and disaster recovery: a writer that has lost its local state can ingest its own records back from the settlement network and reach every tier by re-deriving the per-record child keys.

**That tier is bounded by writer-blind fields, and the bound is exact.** For a blind field the writer has no route: not the identity slot, because it is not a recipient; not the per-field key, because rule 5 of section 9.1 forbids a blind field from declaring `cv`, and regeneration would in any case require the plaintext it is trying to obtain; and not the plaintext, because it holds none. The absence is total and permanent by construction.

What the bound does not reach is everything else, and that is why the carve-out sits at the field rather than at the envelope. The writer keeps the outer wrap, so it keeps the whole audit tier: the header, the signatures, every audit field, and the structure of the blind field's slot including its name, its size and its recipient identifier list. It therefore still replays the record deterministically, still verifies the signatures and the settlement-side integrity check, and still reaches every other private field. Disaster recovery is degraded for exactly one field and intact for the rest of the record.

A reader in this position surfaces the field with the redacted marker and continues. It MUST reach that state by its key resolver declining the field rather than by attempting a key it does not hold, because an attempt aborts the entire decode and destroys the partial access this paragraph describes. Declining is sufficient on its own, on every placement, whether or not the ciphertext still exists.

### 13. Encode flow [#13-encode-flow]

```
Inputs:
  fields[]         per field: { descriptor: {n, sn, pl, cv?}, value,
                                filename?, mediaType?, meta?,
                                recipients?, selfRecipient? }
  auditRecipients[] the outer wrap's identity recipients, with the writer
                    self-recipient already included
  signer            an ES256 signer, root or delegate
  dualSigner?       present only on a key-rotation record

1. Split fields by sensitivity into public, audit and private groups.

2. Build public slots. For each public field:
     if the value is absent and pl == 'ch':  slot = {n, u: true}; continue
     if pl == 'ch':                          slot = {n, v: value}
     else:                                   upload the deterministic encoding
                                             of the value off-envelope;
                                             slot = {n, im: {sha, u, sz}}
     An absent value at pl 'ov' or 'ex' needs no marker and MUST NOT carry one.

3. Build audit slots by the same procedure, into the audit layer's array.

4. Build private slots. For each private field:
     if the value is absent:
         if pl != 'ch':                      REJECT (unrepresentable)
         if filename, mediaType or meta present: REJECT (orphaned metadata)
         slot = {n, u: true}; continue
     cv_i = (descriptor.cv === true)         // exactly true
     if (cv_i ? 1 : 0) + (selfRecipient ? 1 : 0) + count(recipients ?? []) == 0:
         REJECT (unopenable slot)
     plaintext  = deterministicEncode([value, filename?, mediaType?, meta?])
     compressed = LZMA(plaintext, 9, endMarker disabled)
     jwe = GeneralEncrypt(compressed)
     if cv_i:
         { CEK, hash } = calculateSecrets(plaintext, 200000)
         jwe.protectedHeader = {enc: 'A256GCM', iter: 200000, salt: hash}
         jwe.addRecipient(CEK, A256GCMKW)
     else:
         jwe.protectedHeader = {enc: 'A256GCM'}
     jwe.addRecipient(selfRecipient, ECDH-ES+A256KW)   // if present
     jwe.addEachRecipient(recipients, ECDH-ES+A256KW)
     jwe.encrypt()
     if pl == 'ch':  slot = {n, jwe}
     else:           upload the ciphertext bytes off-envelope;
                     slot = {n, je: <jwe minus ciphertext>, im: {sha, u, sz}}

5. Build the header with hdr.fields[] in the author's declared order, public,
   audit and private descriptors mixed as declared.

6. signedBytes = deterministicEncode({hdr, au, pr})

7. sigs = GeneralSign(signedBytes).addSignature(signer, ES256)
                                  [.addSignature(dualSigner, ES256) on rotation]
   with the carried payload set to the empty string.

8. auditLayerBytes = deterministicEncode({hdr, sigs, au, pr})

9. convergent = any private field declares cv === true
   if convergent: { s1_record, hash_record } =
                      calculateSecrets(auditLayerBytes, 200000)

10. outer = GeneralEncrypt(auditLayerBytes)
      if convergent:
        protectedHeader = {enc: 'A256GCM', iter: 200000, salt: hash_record,
                           proto: <profile format identifier>, aid: hdr.aid}
        addRecipient(s1_record, A256GCMKW)
      else:
        protectedHeader = {enc: 'A256GCM',
                           proto: <profile format identifier>, aid: hdr.aid}
      addEachRecipient(auditRecipients, ECDH-ES+A256KW)
      REJECT if the list is empty and the record is not convergent
      encrypt()

11. envelopeBytes = deterministicEncode({proto: <profile format identifier>,
                                        pu, outer})

12. Emit the settlement entry carrying envelopeBytes in its data field.
```

The writer MUST fail fast on any off-envelope upload error: no envelope is emitted if any field's upload fails. This prevents a state in which the envelope references bytes that do not exist. The writer SHOULD NOT attempt to delete already-uploaded bytes for the fields that succeeded; those become orphans for a later sweep to reclaim, which is acceptable precisely because the envelope never reached the settlement network and no binding was ever observed externally.

### 14. Decode flow [#14-decode-flow]

```
Given the envelope bytes:

1.  env = deterministicDecode(envelopeBytes)
2.  Assert env.proto is the format identifier of a profile this reader is
    configured for; refuse otherwise

3.  Handle public slots. For each slot in env.pu:
      // The marker rules are checked FIRST, before any variant dispatch, so a
      // slot claiming absence while carrying a value is refused rather than
      // having one of its two readings silently preferred.
      if the slot has 'u': assert rules 2 to 4 and pl == 'ch'; value = absent
      else if the slot has 'v': value = slot.v
      else if the slot has 'im': resolve the bytes, verify the digest and the
                                 size, then decode
      else REJECT

4.  Decrypt the outer wrap. In whichever order the reader's access allows:
      (a) the convergent self-wrap, available only on a convergent record and
          only to a reader that already holds the audit-layer plaintext;
      (b) an identity slot, unwrapped with the reader's own private key. A
          root-holding reader computes that key from the protected header's
          `aid` under the recipe of section 8.6; a holder of a raw one-time
          slot already has it and needs neither the identifier nor a derivation.
      The decryption step walks the slots either way, so a decoder MUST NOT
      branch on provenance and MUST NOT try to infer it: nothing on the wire
      distinguishes a derived child point from a raw one.
    If no path is available the reader is at the Nothing tier; stop.

5.  auditLayer = deterministicDecode(auditLayerBytes)
    Reject any top-level member outside {hdr, sigs, au, pr}.

5a. Assert protectedHeader.aid == auditLayer.hdr.aid. On mismatch, or on an
    absent or non-text protected-header aid, abort with an integrity refusal.

6.  Assert auditLayer.sigs.payload == ''. Any other value is a signature
    refusal, including the correctly reconstructed attached-payload value.

7.  signedBytes = deterministicEncode({hdr, au, pr})

8.  Verify each signature against base64url(signedBytes) as detached content,
    resolving each signer's verification key from its identifier and the
    header's signer scope. Try the current encoding profile first, then the
    superseded integer shape once. If none verifies, refuse.

9.  Handle audit slots exactly as public slots were handled in step 3.

10. Handle private slots. For each slot in auditLayer.pr:
      // Checked BEFORE the authorisation branch, deliberately: an unset field
      // carries no ciphertext, so being unauthorised is not meaningful for it,
      // and the redacted marker would assert that a withheld value exists.
      if the slot has 'u':
          assert rules 2 to 4 and pl == 'ch'; value = absent; continue
      Validate the slot: its shape, its manifest shape, the URI scheme
      allowlist, and, if the resolver may decline, everything the decryption
      step would have validated (section 9.1 rule 2).
      Consult the key resolver, supplying the field's identity recipient
      identifier list.
      if the resolver DECLINES: value = redacted marker; continue
                                // no byte resolution is attempted, on any
                                // placement, so absent bytes cannot raise
      if the slot is in-record:  jweToDecrypt = slot.jwe
      else:                      resolve the bytes for this field, verify the
                                 digest and the size, and reinstate them as the
                                 ciphertext of slot.je
      compressed = decrypt(jweToDecrypt, key)
      plaintext  = LZMA-decompress(compressed)
      [value, filename, mediaType, meta] = deterministicDecode(plaintext)

11. Reconstruct the operation's arguments from the header and the merged
    values, in hdr.fields order.
    // An unset field occupies its OWN argument position carrying no value and
    // is never skipped. Omitting an entry for a mid-signature optional shifts
    // every later argument one place left and silently mis-dispatches.
```

### 15. Decode-output field markers [#15-decode-output-field-markers]

A decoded field's value is the recovered plaintext on the happy path, or one of three markers standing for a value the reader did not get. **This section specifies their semantics. It deliberately does not prescribe how an implementation represents them**, beyond the requirements below, which are about observable behaviour rather than about a type.

| Marker          | The decoder surfaces it when                                                                                                                                                                                                                |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **redacted**    | The key resolver declined the field, meaning the reader is not a recipient of it. A value exists and this reader is not authorised for it.                                                                                                  |
| **unavailable** | The bytes exist somewhere the reader cannot reach: an externally placed field whose store rejects the request as not-found or access-denied, or for which the reader has no store configured at all. It may resolve for a different reader. |
| **erased**      | The source was asked, answered, and holds nothing. This is what an honoured deletion request looks like from the reader's side. It will not resolve for anybody, ever.                                                                      |

The normative requirements:

1. **The three MUST be distinct and MUST NOT be collapsed into one another.** A consumer that cannot tell them apart cannot tell a permissions boundary from a deletion, which are different facts with different remedies.
2. **None of them MUST be rendered as an empty or absent value**, and none is the declared-but-unset marker of section 7. An unset field has no value and never reaches the key resolver; a redacted field has a value this reader may not read.
3. **A reader that is not a recipient MUST decline, and declining MUST NOT abort the decode.** Attempting a key the reader does not hold reaches the decryption step, which throws, and that aborts the whole decode rather than degrading one field. The two outcomes are not interchangeable, and a decoder MUST NOT turn a decline into an aborted decode, nor an attempted wrong key into a silent redaction. Both directions destroy the guarantee.
4. **A marker MUST NOT be treated as an authenticated claim.** It records only what the local decoder produced. It is not a security claim, and nothing downstream may take one as proof that a value was withheld, that an erasure happened, or that an authorisation went a particular way, nor use one to decide what to tell a third party. Branch on a marker to shape your own handling; do not treat it as evidence.
5. **A marker MUST NOT be written into an outbound record.** A marker records that some reader did not get a value, so anchoring one states that permanently in the writer's name. **The refusal MUST cover every value that becomes part of the outbound record**, not one category of them: an implementation that refuses markers among the operation's arguments while a separately resolved field value reaches the encoder untouched has enforced the rule at one of its doors. The refusal belongs at the encode boundary, and **any write path that reaches the settlement network without passing that boundary MUST enforce the same refusal at an earlier gate it does pass**; such an earlier refusal is not a redundant duplicate of the boundary's.
6. **The refusal MUST recognise every spelling that encodes to marker bytes**, not only the most obvious in-memory shape. The deterministic profile normalises several container kinds to the same canonical map, so a value that is not literally a plain object can still encode to bytes indistinguishable from a marker. A write boundary MUST therefore ask what a value will encode as, not merely what it structurally is.
7. **The refusal MUST NOT be placed inside the canonical encoder.** That encoder also reproduces bytes for signature verification over values taken straight off the wire, where a policy refusal would throw before the signature is verified, on unauthenticated remote input, and would yield a failure the admission path cannot classify.
8. **A decoder MUST refuse a decrypted plaintext that structurally resembles a marker without being one of its own**, at every site that can emit a field value, and MUST classify that refusal as a decode failure rather than an integrity failure: the bytes authenticated correctly, and what is wrong is a claim the content makes. The check is at the top level of the field value, which is sufficient because that is where every consumer tests it, and going deeper would make the refusal reachable from remote content again.
9. **Recognition of a marker MUST fail closed.** Where an implementation recognises markers structurally, a value that cannot be inspected without raising MUST be reported as not a marker rather than allowed to propagate the failure. That is the true answer and not a degraded one: the question is whether this is one of ours, and a value we cannot read is not. Where identity can be decided without inspecting the value, it MUST be decided first, so that a genuine marker is recognised with no inspection at all.
10. **A write boundary that re-reads the value it checked MUST make the re-read honest.** Refusing a marker means reading the value, and the encoder then reads it again, so a value that answers differently on the second read is checked as ordinary and signed as a marker. The boundary MUST own each outbound value across the whole check-and-use interval, by reading it once into a copy the boundary holds and judging that copy. Ownership is bounded in two ways that are part of the requirement rather than concessions to it: it applies to the values the encoder turns into a map, so a byte payload still travels by reference; and it is required at the top level only, because a nested mutation cannot turn the anchored value into a marker.

### 16. Algorithm identifiers [#16-algorithm-identifiers]

| Identifier       | Use                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `A256GCM`        | Content encryption for the outer wrap and for each per-field JWE                                                        |
| `A256GCMKW`      | The convergent self-wrap, keyed by the record-level `s1` at the outer layer and by the per-field key at the inner layer |
| `ECDH-ES+A256KW` | Every identity recipient, at both layers                                                                                |
| `ES256`          | ECDSA over P-256 with SHA-256, for the signatures                                                                       |

Signature values are the 64-byte fixed-width form of RFC 7518 §3.4, not DER. Public keys on the wire are 33-byte SEC1-compressed P-256 points, rendered as 66 hex characters where an identifier is a text string. Digests are 32-byte SHA-256 outputs.

Implementations MUST use a JOSE implementation for these primitives and MUST NOT hand-roll them.

### 17. Security considerations [#17-security-considerations]

#### 17.1 Public fields leak by design [#171-public-fields-leak-by-design]

Public fields are plaintext to any observer. Writers MUST use them only for values that are safe to publish. Putting sensitive data in a public field leaks it to everyone, permanently.

#### 17.2 The audit tier sees private slot structure [#172-the-audit-tier-sees-private-slot-structure]

Audit recipients see private field names and approximate sizes without holding per-field decryption rights. The size surface differs by placement: an externalised field carries its size explicitly in its manifest, while an in-record field discloses it as the length of the ciphertext in the slot. Neither placement conceals size; only the member that reveals it changes.

If field names are themselves sensitive, they leak at the audit tier. Writers MAY use opaque field names and map them to semantics out of band.

#### 17.3 The convergent confirmation oracle [#173-the-convergent-confirmation-oracle]

A party holding a specific field's plaintext can confirm that a record contains exactly that plaintext. This is usually desired, since it is what content-addressed auditing means, but against an adversary who is testing a guess it is a confirmation oracle.

**The cleanest mitigation is not to ask for it.** The property is opt-in and defaults to off, so a field that omits `cv` does not carry the oracle and needs no padding.

The oracle was never only the recipient slot: `salt` is the SHA-256 of the plaintext and rides in the protected header, which at the outer layer is readable with no key whatsoever. That is why `iter` and `salt` are removed together with the recipient rather than the recipient alone; keeping the header members would preserve the entire confirmation surface while delivering none of the capability it exists for.

Where a field does declare `cv` and the oracle matters, the author MAY inject random padding before encoding.

#### 17.4 Size-oracle leakage [#174-size-oracle-leakage]

Field size is visible at the audit tier in both placements, so a mitigation must cover both. Padding to standard sizes is that mitigation. **Where it is applied matters**: an application that pads SHOULD pad the plaintext value before encryption, because ciphertext length tracks plaintext length once compression and AES-GCM have run, so padding the slot afterwards conceals nothing. Nothing in this format pads on the author's behalf, and padding is not mandatory for any field class.

#### 17.5 Outer-wrap integrity [#175-outer-wrap-integrity]

The outer wrap's AES-256-GCM tag covers the entire audit layer. Any modification breaks the tag and decryption fails. This holds identically whether the payload is attached or detached, so the choice of detached signatures is a transport optimisation with no security delta.

#### 17.6 Decoding untrusted input [#176-decoding-untrusted-input]

Both the outer bytes and, at any exported decoding entry point, the slots themselves arrive from parties the decoder does not trust. Four requirements follow, and each was learned by an implementation losing it.

**Read each caller-supplied member exactly once.** A member read to make a decision and read again to act on that decision is two values with one check between them, because a caller-supplied object can answer differently per read. Every member of a slot reaching an untrusted boundary MUST be read a single time into a local, and every subsequent validation, diagnostic, dispatch and return MUST consume that local. Where a helper needs a member it MUST receive the value rather than the containing object, so that it is structurally incapable of consulting the caller a second time. The failures this prevents are concrete: a field name that passed the shape gate differing from the name returned, a key selected from one protected header while the decryption ran against a different one, and a URI approved by the scheme gate differing from the URI actually requested.

**The single-read rule is transitive.** Reading a member once establishes which object was received and establishes nothing about that object's own members, which come from the same caller. A nested caller-supplied object MUST therefore be snapshotted into an inert copy before any of its members is inspected, its validation MUST run against that snapshot, and every downstream consumer MUST receive the snapshot. Any byte array carried by such a snapshot MUST be copied rather than referenced, because the caller retains the original and a mutation landing while a fetch is in flight moves a digest out from under the comparison it feeds. Where a byte array cannot be copied at all, the snapshot MUST refuse rather than fall back to referencing it.

**A transitive snapshot MUST be bounded, in depth and in breadth.** Recursion over caller-supplied structure trades a correctness hole for a denial-of-service one unless it is bounded. A value nesting deeper than the bound MUST be refused as a structured refusal rather than allowed to exhaust the stack. The snapshot's cost MUST be proportional to the members the caller actually supplied and never to a size the caller merely declares, so an array MUST be snapshotted by visiting the members that exist rather than by walking to a declared length, and the declared length MUST be preserved rather than recomputed so that downstream length checks still see what the caller sent. A node reachable by more than one path MUST be snapshotted once and its copy reused, because re-walking a graph per path costs work exponential in its depth while its size stays small. That reuse MUST NOT relax the depth bound: a subtree first reached shallowly and reached again below the bound MUST still be refused.

**Every caller-supplied string interpolated into a refusal MUST be bounded and escaped at one place.** Field names carry no length bound anywhere in this format, so a refusal message is attacker-influenced by the time an operator reads it. Bounding site by site as each is noticed is what produces successive amplification defects on one message; a single shared renderer is the requirement. Truncation MUST cut on code-point boundaries, because a cut splitting a surrogate pair yields text that is not well-formed UTF-8 and that a strict text store rejects, losing the diagnostic record entirely. **The escaped class is Unicode general category Cc, that is U+0000 to U+001F and U+007F to U+009F, plus U+2028 and U+2029, plus lone surrogates**, and an implementation MUST state that class itself rather than inherit it from a serialiser's own escaping rule: the common JSON escaping leaves the whole C1 block and both line separators raw, so a value carrying U+0085, U+2028 or U+2029 can end a line for any Unicode-aware log reader and U+009B can open a terminal control sequence as a single character.

**A refusal that reports a foreign failure value MUST NOT inspect it.** Classifying by the value's basic type is the whole classification, because that is the only question about a foreign value that the value cannot intercept. A primitive keeps its detail, bounded and escaped; anything else is reported by its type alone. Containing the inspection in an exception handler is not sufficient and MUST NOT be presented as though it were, because a handler contains an interceptor that raises and does nothing about one that returns, and a returning interceptor performs unbounded work and then supplies the text that gets rendered. The cost is accepted deliberately: an ordinary library failure loses its wording too, because nothing distinguishes it from a hostile one without asking. An implementation SHOULD still carry a fixed first-party label chosen by the branch that raised, which asks the value nothing and preserves the distinction between a merely malformed record and an input outside the profile's domain, the second of which is a probe.

**Any conversion whose cost scales with a producer-chosen operand MUST be decided by a comparison against a fixed bound before the conversion runs**, and reported by shape beyond that bound. A cap applied to the rendered output does not bound the work that produced it. This binds the class and not a list of instances: rendering a large integer, materialising a producer-sized description, and converting a magnitude in order to decide whether it is too large to convert are three instances of one shape, and a conforming implementation audits its own conversions against the rule rather than against the examples.

#### 17.7 Interoperability across versions [#177-interoperability-across-versions]

Two directions, both normative, and one of them is easy to assume and get wrong.

**A new decoder MUST decode an old envelope.** Records written before the convergent opt-in existed are convergent throughout and declare no `cv`. The backing rule of section 6.1 is therefore deliberately one-directional: convergent material without a `cv` descriptor is exactly the shape of every such record and MUST NOT be refused.

**An old decoder MUST decode a new envelope, and there is no decoder version floor for the convergent opt-in.** Two structural reasons. The descriptor member set was never closed: the descriptor gate validates the name, sensitivity and placement and enumerates no allowed-member list, and the audit-layer shape gate rejects unknown members only at the top level, so an added descriptor member passes an older gate untouched. And no decoder reads `iter` or `salt`: the production key resolver derives the outer key from the protected header's record identifier and never consults the convergent members, so their absence on the default path changes nothing an older decoder depends on.

**This is a promise rather than an observation**, and a conforming implementation SHOULD pin both properties with tests rather than pinning only the outcome, because an outcome-only test would still pass if a later change closed the descriptor member set for an unrelated reason. The value of the promise is that a deployment can upgrade writers and readers independently.

Note that this is not a general rule about every format change. A change whose new member is **ignored** by older decoders sets no floor; a change whose new member is **refused** by them does. The detached-payload change is of the second kind: an envelope with a non-empty carried payload is rejected outright by a decoder implementing section 8.3, with no compatibility shim.

**Byte parity with the previous format generation ends at the convergent opt-in.** The primitives were inherited verbatim so that identical inputs would produce identical bytes, and the previous generation always derives. An envelope produced on the default path is therefore not byte-identical to what that generation would produce for the same input, because it lacks the convergent recipient and the two protected-header members. Nor does an envelope whose fields all declare `cv` match, and it is worth being explicit about why: the marker serialises into the header, so it changes the audit-layer bytes, and those bytes are both what the signatures cover and the sole derivation input to the outer wrap, whose `salt` is their SHA-256. A `cv` member therefore moves the signed bytes, the outer salt and the record-level `s1` together. What survives byte for byte is the per-field convergent construction itself: for a field that declares `cv`, the primitive, the iteration count, the convergent recipient and the two header members are identical.

### 18. Open questions [#18-open-questions]

* **Compression of public and audit plaintext slots.** Those values are currently uncompressed. For a large externalised plaintext value, compressing before hashing would reduce off-envelope size at the cost of a second byte definition to pin.
* **The record-level iteration count.** It is pinned at 200000. For a large audit layer the derivation can cost hundreds of milliseconds, and a lower count for the record-level derivation specifically could be considered on evidence.
* **Slot array ordering.** The header's descriptor list is in author-declared order while the three slot arrays group by sensitivity, so readers match slots back to descriptors by name. Keeping the slot arrays in descriptor order with placeholder entries would simplify lookup at a cost in wire size.
* **Signature coverage of public fields.** Signatures do not cover public slots today. Whether to extend coverage through an auxiliary mechanism depends on the adversary model.
* **Third-party signature verification.** Deriving the signing key against a wildcard counterparty would let any holder of a signer's root public key verify identity binding, at the cost of exposing the key-identifier stream to that same audience. It would have to move in lockstep with the settlement-side locking recipe.

***

## Field placement [#field-placement]

### 1. Scope [#1-scope]

Placement controls only where a field's value bytes live. The JOSE wrappers, meaning the protected header, the recipient list, the initialisation vector and the authentication tag, stay inline in every case, and the outer encryption wraps the full audit layer in every case. An observer therefore learns nothing about which fields are placed where, which URIs are referenced, or what digests they have. The privacy properties of the envelope hold uniformly across all three placements.

Each field descriptor carries a placement code `pl`. This section specifies the semantics of that code, the resolution protocols at encode and decode time, the availability and failure semantics, the retention duties, and the integrity binding that makes off-envelope placement safe against tampering.

### 2. The three placements [#2-the-three-placements]

#### 2.1 `pl: "ch"`, in-record [#21-pl-ch-in-record]

The field's data sits inline at its layer position. There is no off-envelope storage.

```
sn: "pu"  ->  { n, v: <value> }   in the top-level public array
sn: "au"  ->  { n, v: <value> }   in the audit layer's audit array
sn: "pr"  ->  { n, jwe: <JWE> }   in the audit layer's private array
```

Use when the plaintext is small, as a rule of thumb under a kilobyte; when the field is audit-critical, so that everyone who reads the record can verify it; or when the value must never be unavailable.

Avoid when the field is large or rarely read. The record is permanent, so the storage cost is paid forever.

#### 2.2 `pl: "ov"`, overlay [#22-pl-ov-overlay]

The bytes travel on the overlay submission channel alongside the record's admission, as a value the admitting overlay node persists keyed to the record and replicates to peer nodes hosting the same topic. Readers receive the bytes alongside the record through the overlay's per-topic lookup.

The URI form is `overlay://<topicId>/<contentHash>`, where the content hash is the lowercase hex SHA-256 of the stored bytes.

Use when the data is shared among known participants; when availability matters and one participant being offline must not break decoding; and when the data is canonical and the participants want it permanently retained.

Avoid for very large values repeated across every participant's node, when the participants are unwilling to carry the replicated storage cost, or when the data is owned by a single operator.

#### 2.3 `pl: "ex"`, external [#23-pl-ex-external]

The bytes are stored in an operator-owned object store, addressed by a URI in one of the schemes of section 4. The operator owns the lifecycle: retention, backup and deletion.

Use for single-operator deployments, for large values, or where an operator already has established storage and replication across every participant would be prohibitive.

Avoid where the data must remain available even if the operator disappears, or for audit-critical fields that third-party verifiers expect to resolve indefinitely.

#### 2.4 Externalised plaintext [#24-externalised-plaintext]

For a public or audit field placed externally, the plaintext value rather than a JWE is stored off-envelope, and the slot carries the integrity manifest directly:

```
{ "n": <fieldName>, "im": { "sha": <32-byte string>, "u": <text>, "sz": <uint> } }
```

The reader fetches the bytes, verifies that their SHA-256 equals `im.sha`, and decodes them under the deterministic profile to recover the value.

For a **public** externalised field the bytes are publicly fetchable and the URI is visible to any observer, because the slot sits outside the outer wrap. For an **audit** externalised field the bytes are still fetchable by anyone holding the URI, but no observer sees the URI, because the slot sits inside the outer wrap. That combination is the right one for large audit-grade data that auditors should be able to fetch but that should not be indexed by observers.

### 3. The integrity manifest [#3-the-integrity-manifest]

```
im = {
  "sha": <32-byte string>,   // SHA-256 of the externalised bytes
  "u":   <text>,             // resolver URI
  "sz":  <uint>              // exact byte count
}
```

Exactly three members. A decoder MUST reject a manifest carrying any other member.

No separate authenticated-data member is carried at this layer. For an encrypted field, JOSE already covers the cryptographic associated data through the base64url protected header, which is part of the detached JWE and therefore travels inline. The manifest binds the opaque off-envelope bytes to their digest; once the reader reinstates the ciphertext, the decryption step enforces cryptographic integrity end to end.

#### 3.1 What the digest covers [#31-what-the-digest-covers]

`sha` is the SHA-256 of the exact byte sequence stored at `u`. Two cases:

* **Encrypted fields**: the externalised bytes are the JWE's ciphertext member, decoded from base64url into raw bytes for both hashing and storage.
* **Public fields**: the externalised bytes are the deterministic encoding of the field value itself, with no JOSE involvement.

#### 3.2 Verifying resolved bytes [#32-verifying-resolved-bytes]

A resolver is never trusted to have verified anything. The decoder MUST perform the checks itself, in this order:

1. **Refuse a value that is not a byte sequence.** The resolver interface asks for bytes; at an untrusted boundary that is a request rather than a guarantee, and this is where it is measured. A resolver that answered with something other than bytes has answered, so this is not absence, and what it answered cannot match the commitment. This is an integrity refusal and MUST route exactly as a digest mismatch does.
2. **Refuse an oversized answer before copying it.** Compare the answered length against the manifest's declared size and refuse if the answer is larger. This is a constant-cost check placed ahead of a linear-cost copy, so that a resolver answering a twelve-byte field with megabytes does not get all of them copied into decoder storage first. The comparison MUST read the length through the same intrinsic accessor the copy will use, because a shadowed length member would let the gate read a different number from the operation it guards. The check is one-sided on purpose: only an oversized answer makes the copy cost more than the manifest authorises.
3. **Copy the bytes into decoder-owned storage.** The size and digest checks establish a property of bytes at an instant, and returning the resolver's own array would let that property expire the moment the function returned. Where the bytes cannot be copied, because the underlying buffer is shared with the caller or has been detached, the decoder MUST refuse rather than fall back to referencing them.
4. **Check the size against the manifest** on the copy. This is kept even though step 2 exists: a resizable buffer can shrink between the two reads, so step 2 is an economy and this is the guarantee about the bytes actually returned.
5. **Compute SHA-256 over the copy and compare against the manifest**, using a constant-time comparison over the raw digest bytes.

On any mismatch, the record is refused as an integrity failure and the runtime never sees it.

### 4. URI schemes [#4-uri-schemes]

| Scheme                              | Channel | Semantics                                                                                                                                            |
| ----------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `overlay://<topicId>/<contentHash>` | ov      | The bytes ride the overlay submission channel, are persisted by the admitting node, replicated to peers, and returned alongside the record on lookup |
| `s3://<bucket>/<key>`               | ex      | S3 or an S3-compatible store                                                                                                                         |
| `gs://<bucket>/<object>`            | ex      | Google Cloud Storage                                                                                                                                 |
| `file://<absolute-path>`            | ex      | Local filesystem, for development and offline operators                                                                                              |
| `https://<host>/<path>`             | ex      | Generic HTTPS, for an operator-hosted origin                                                                                                         |

**Implementations MUST reject any scheme outside this list.** This forecloses server-side request forgery through arbitrary schemes. Operators MAY additionally configure host allowlists for `https://` to bound that risk further per deployment.

**The two channels MUST NOT be crossed.** The `overlay://` scheme is answered only by the overlay arm of the field resolver, and the external blob-store interface MUST reject an `overlay://` URI with an explicit error so that a misconfigured caller cannot route overlay bytes through the external channel. Correspondingly, the encoder MUST NOT call the external store for a field placed on the overlay. The two placements carry different guarantees, replicated-and-shared against source-private, and collapsing them at either the encoder or the decoder collapses the guarantee.

**A scheme in the allowlist for which no adapter has shipped MUST be refused as an integrity failure**, in both the store-configured and no-store paths, rather than degraded to the unavailable marker. Two reasons. It keeps the two paths symmetric, since the in-store dispatch throws for an unimplemented scheme anyway. And it is forward-compatible for signed records: a reader that accepted such a URI as unavailable today would surface a different argument list once the adapter shipped, changing observed behaviour with no change to the record.

#### 4.1 Client-derived external URIs [#41-client-derived-external-uris]

Where a consumer signs a record before the bytes reach the operator, the signed URI is fixed at signing time while the operator owns the storage address grammar. The two are reconciled without changing the grammar:

1. **Publish.** The operator publishes its existing address grammar as a template, with the variable positions exposed as literal placeholders standing for the record identifier and the field name, for example `s3://{bucket}/{prefix}{recordId}__{fieldName}.cbor` or `file://{rootDir}/{recordId}__{fieldName}.cbor`. The placeholder spellings are part of the template grammar and both sides MUST agree on them.
2. **Derive and sign.** The consumer derives the URI client-side from the record identifier and the field name against the published template, embeds it in the manifest, and signs the record.
3. **Upload.** The consumer sends the raw bytes alongside the signed record.
4. **Validate by derive-and-compare, fail closed.** The operator derives the canonical URI its own adapter would generate for that record identifier and field name, and asserts that the record-declared URI is byte-identical to it. Any divergence MUST refuse the upload. This is the forgery guard: a URI the operator's adapter would not itself generate cannot steer a write outside the operator's own namespace. The content digest stays in the manifest and is verified separately; it is not part of the path.

**A template MUST resolve only to schemes the operator's store natively handles.** Templates resolving to `https://` are forbidden, because such a template would let derive-and-compare pass for a URI under an operator-controlled host that nonetheless redirects elsewhere, reintroducing exactly the redirect-style forgery that the scheme allowlist and the redirect rule exist to prevent.

### 5. Encode side [#5-encode-side]

For each field, the writer builds the appropriate slot. Where the placement is not in-record, the path diverges after the JWE, or the plaintext value bytes, are constructed:

1. **Build the JOSE object as if the placement were in-record.** For a private field this means deriving any convergent material, compressing the encoded tuple, and encrypting. For a public or audit field there is no JWE, and the bytes are the deterministic encoding of the value.
2. **Split out the ciphertext**, for a private field: the detached JWE is the JWE with its ciphertext member removed, and the bytes are that member decoded from base64url into raw bytes. For a public or audit field the bytes are the encoded value.
3. **Compute the manifest**: the SHA-256 of the bytes and their exact length.
4. **Deliver the bytes.** For overlay placement, append them to the submission's off-envelope value list and construct the URI as `overlay://<topicId>/<hex digest>`. For external placement, store them and construct the URI per the operator's grammar.
5. **Populate the manifest** with the digest, the URI and the size.
6. **Emit the slot** at its layer position: `{n, je, im}` for a private field, `{n, im}` for a public or audit one.

**The writer MUST fail fast on any storage error.** No envelope is emitted if any field's delivery fails, which prevents a record that references bytes that do not exist. The writer SHOULD NOT attempt to delete bytes already stored for fields that succeeded; those become orphans for a later sweep to reclaim. That is acceptable precisely because the record never reached the settlement network, so no binding was ever observed externally.

### 6. Decode side [#6-decode-side]

**Precedence.** For a private slot, the decode order of the envelope section takes precedence over the flow below: the reader consults its key resolver before any byte resolution, and a declined field short-circuits to the redacted marker without any resolution step running, so its bytes are never looked for and their absence cannot raise. This holds on all three channels. The steps below describe the flow for a field the reader is authorised for, and for public and audit slots, which have no authorisation dimension.

For each slot:

1. Look up the field's descriptor by name and read its placement.
2. If the placement is in-record, decode inline; no resolver is invoked.
3. Otherwise, request the field's own bytes from the resolver using the manifest URI, applying the timeout and retry policy of section 7.
4. Verify the resolved bytes per section 3.2.
5. Branch on the slot's layer position. For an encrypted field, reinstate the JWE by reinjecting the base64url of the resolved bytes as its ciphertext member and decrypt, which verifies the authentication tag over the protected header as associated data. For a public or audit field, decode the bytes directly; the SHA-256 is then the sole integrity check.
6. Hand the decoded field onward.

**Each field pulls its own bytes.** A decoder MUST NOT require a single concatenated payload covering the whole record: it computes each field's byte window from the sizes the record already declares, and asks its resolver for that field's bytes alone. This is what allows the authorisation consult to precede resolution, which in turn is what makes per-field degradation work.

#### 6.1 Manifests and the outer wrap [#61-manifests-and-the-outer-wrap]

Audit and private manifests live inside the audit layer, so an observer sees only the outer ciphertext and the top-level public array and learns nothing about their placement, URIs or digests. Public manifests sit outside the outer wrap and are visible to any observer by design; an author who wants a manifest hidden uses the audit sensitivity instead.

Only parties who can decrypt the outer layer see audit and private manifests and can resolve those bytes at all. Per-field recipient lists then further constrain which of those parties can decrypt each private field even after resolution.

### 7. Availability and failure handling [#7-availability-and-failure-handling]

Off-envelope placement introduces an availability dimension the settlement network does not have: the bytes must be fetchable to decode a field the reader is **authorised for**. A declined private field decodes to the redacted marker with no fetch at all, which is what keeps an erasure of its bytes a non-event on replay.

#### 7.1 Timeout and retry [#71-timeout-and-retry]

The default fetch timeout is **5 seconds** per value, configurable per deployment. On timeout, the request escalates to retry, and on retry exhaustion to the degradation rules below.

For overlay placement, the reader tries other nodes hosting the topic; all known peers are attempted before escalating. For external placement, the reader makes three retries with exponential backoff at 250 ms, 500 ms and 1 s, and treats anything beyond that as unavailable.

#### 7.2 Overlay bytes that are not in hand: three causes, and only two are failures [#72-overlay-bytes-that-are-not-in-hand-three-causes-and-only-two-are-failures]

The overlay channel guarantees end-to-end byte preservation, since every receiver on the topic gets the bytes alongside the record. So when a reader does not have those bytes, exactly one of three things has happened, and they do not share an outcome:

* **The bytes arrived damaged.** A digest or size mismatch on an `overlay://` URI is an integrity refusal regardless of field criticality, and the record is dead-lettered as an integrity failure.
* **The reader could not ask.** No resolver is wired, or the resolver cannot reach its source, so the reader never learned anything about the bytes. This MUST raise a **distinguishable subtype of the integrity refusal**, so that the integrity routing is preserved by construction while a caller can still recognise the case structurally rather than by matching message text. **This is a transient condition and MUST be treated as one**: refuse, do not dispatch, retry.
* **The source answered and holds nothing.** The resolver answered and returned no bytes, which is what an honoured erasure looks like from the reader's side. That field degrades to the **erased** marker and the rest of the record decodes and dispatches. **It is not an integrity failure**: nothing is corrupt and nothing is unreachable.

**The distinction that carries this section is answered-without-bytes against could-not-ask.** Collapsing the second into the first, by calling every missing-bytes case an integrity failure, means that honouring one deletion request destroys whole records.

#### 7.3 External unreachability is application discretion [#73-external-unreachability-is-application-discretion]

External bytes stay at the source operator's store; only the manifest travels with the record. Other readers see the manifest and cannot resolve the URI without operator-specific capability. &#x2A;*Cross-environment unreachability is the privacy boundary doing its job, not a failure mode.** A reader on a different operator's footprint MUST ingest the record and surface the field as gated rather than dead-letter it.

The **unavailable** marker is surfaced for exactly three cases, all of which mean well-formed bytes that this reader cannot reach:

* not-found from a configured store, meaning the URI is valid and the bytes are not on this operator's store;
* access-denied from a configured store, meaning the URI is valid and this caller lacks credentials;
* no store configured at all, provided the URI scheme still passes the allowlist gate.

The following are integrity refusals and MUST NOT be surfaced as unavailable:

* a digest or size mismatch on bytes that were served, since corruption is always an integrity failure whatever the placement;
* bytes that match the manifest but cannot be decoded under the deterministic profile, since the manifest then signed corrupt content;
* a URI scheme outside the allowlist, refused before either the in-store or the no-store branch;
* a URI scheme inside the allowlist for which no adapter has shipped, per section 4.

**The overlay twin of the unavailable marker is the erased marker, and the two are deliberately distinct.** Unavailable says "these bytes exist somewhere I cannot reach", which on the external channel is the privacy boundary working and which may resolve for a different reader. Erased says "the source answered and holds nothing", which is what an honoured deletion looks like and which will not resolve for anybody, ever. An application that cannot tell them apart cannot tell a permissions boundary from a deletion, so they MUST never be collapsed, and neither is ever rendered as an empty or absent value.

An application handler decides per field. Where a field is required for dispatch, it asks for the value and the request is refused as gated if the value is any marker; the record is then dead-lettered with a gated reason distinct from an integrity failure. Where a field is optional, the handler reads the value directly and handles the marker itself, and the record dispatches.

This makes criticality an application-layer choice rather than a framework gate.

#### 7.4 Failure outcomes [#74-failure-outcomes]

| Channel | Cause                                                             | Outcome                                                                                                         |
| ------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| ov      | No resolver wired, or the resolver cannot reach its source        | Integrity failure, through the distinguishable could-not-ask subtype. Transient: refuse, do not dispatch, retry |
| ov      | Resolver answered and holds no bytes                              | Not a dead-letter. That field surfaces as erased and the record dispatches                                      |
| ov      | Digest mismatch                                                   | Integrity failure                                                                                               |
| ov      | Size mismatch, whether short or overlong                          | Integrity failure                                                                                               |
| ex      | Digest mismatch on resolved bytes                                 | Integrity failure                                                                                               |
| ex      | Size mismatch on resolved bytes                                   | Integrity failure                                                                                               |
| ex      | Bytes match the manifest but cannot be decoded                    | Integrity failure                                                                                               |
| ex      | URI scheme outside the allowlist                                  | Integrity failure                                                                                               |
| ex      | URI scheme in the allowlist with no adapter shipped               | Integrity failure                                                                                               |
| ex      | Store rejection on a supported scheme, not-found or access-denied | Not a dead-letter. Field surfaces as unavailable and the record dispatches                                      |
| ex      | No external store configured and the scheme is in the allowlist   | Not a dead-letter. Field surfaces as unavailable and the record dispatches                                      |
| any     | The handler required a field that is a marker                     | Gated, distinct from an integrity failure                                                                       |

### 8. Replay and retention [#8-replay-and-retention]

At replay, potentially years after the record was written, the stores must still resolve. This is an operator duty.

* **Overlay**: participants MUST retain the bytes for the lifetime of the deployment. Admission is permanent, and operators SHOULD NOT prune overlay values.
* **External**: the operator MUST retain the bytes per its retention policy. Losing them is a data-loss event for the affected records. Operators SHOULD back external bytes up on the same cadence as their record store and their key custody material.

#### 8.1 A reader that needs overlay bytes fetches them, and never fabricates them [#81-a-reader-that-needs-overlay-bytes-fetches-them-and-never-fabricates-them]

This applies to any reader that meets an overlay-placed field outside live admission: a replay or a projection path rather than the admission pipeline. Such readers source their **rows** from local storage, and that is a fact about where the rows live, not a restriction on where the **values** may come from. The retention duty above is discharged at the overlay and not in each participant's local store, because the overlay is where those bytes were deliberately placed. **The remedy for a missing value is to ask the overlay**, which is what the per-field resolver exists to do, so a reader with no resolver wired is an incomplete deployment rather than a correct one.

Four outcomes, and the distinction that carries them is again answered-without-bytes against could-not-ask:

| Situation                                                            | Outcome                                                                                                |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| The reader is not a recipient of the field                           | Redacted, with no resolution attempted, on any channel. Not a fabrication: the bytes were never needed |
| The field is needed, is on the overlay, and the overlay is reachable | Fetch it, including during a boot or catch-up phase                                                    |
| The overlay is unreachable, meaning a transport failure              | Transient. Refuse, do not dispatch, do not report ready, retry. MUST NOT degrade                       |
| The overlay answers and does not hold the bytes                      | Erased. Degrade that field alone, decode the rest, dispatch                                            |

Normative requirements for any such reader:

1. **It MUST resolve the field through a resolver when it needs the value and the source is reachable.** It MUST NOT refuse merely because the bytes are absent from local storage. The overlay is a service this deployment may depend on, and needing it is not a defect.
2. **A field the reader is not a recipient of MUST reach the redacted marker without any resolution attempt**, on this channel as on every other. This is not a fabricated value and not a degradation: the bytes were never required, so their presence or absence is not a fact about this record.
3. **A transport failure MUST be treated as transient.** The reader MUST refuse the record, MUST NOT dispatch it with the field absent, defaulted or degraded to any marker, MUST NOT report itself ready, and MUST retry. Dispatching would rebuild application state that never existed, which is unrecoverable in a way that a refusal is not.
4. **A resolver that answers and holds no bytes MUST degrade that field alone to the erased marker**, decode the remaining fields and dispatch. Treating this as an integrity failure would mean one person's deletion request destroys whole records, which is the outcome this class exists to prevent.
5. **The refusal in requirement 3 MUST identify overlay placement as the cause**, distinguishably from a corrupt or truncated value, so that an operator can tell "I could not reach these bytes" from "these bytes are damaged". A caller MUST be able to recognise it structurally rather than by matching message text. The corrupt, short and overlong cases keep the base refusal class, because bytes that arrived wrong are a different fact from bytes never supplied.
6. **No refusal may render record-derived content into operator-facing output**, in particular the field name or the resolver URI. Field names are typed as bare text with no charset and no length bound, so they are attacker-influenced by the time a storage-backed reader sees them. The field name remains available as structured data on the refusal for in-process callers that do not render it.

### 9. Garbage collection [#9-garbage-collection]

**Overlay.** Admitted values are permanent and there is no collection at the overlay layer. The storage cost is paid by the participants.

**External.** Two duties:

* **Orphan collection.** A stored value with no record referencing it, whether because a record was deleted, a deployment migrated, or bytes were uploaded to the wrong place, is a candidate for deletion. Implementations scan the manifests of stored records for referenced URIs and treat the remainder as orphans.
* **Retirement.** When a writer is retired, its external bytes MAY be cold-archived or deleted per operator policy. &#x2A;*Retention MUST outlast any legal or regulatory hold on the underlying data.**
* **Dry run by default.** Any collection tool MUST default to reporting rather than deleting, and MUST require an explicit flag to remove anything. A misconfigured path should cost a report, not a deletion.

### 10. Placement migration [#10-placement-migration]

Placements are immutable per record in this version. A field's bytes cannot be moved from one channel to another after the record is written.

A future version may specify migration through a compensating record that declares a new URI and digest for a prior record's field, with readers preferring the latest reference at decode time and the original bytes becoming eligible for collection after a grace period. That is a sketch and is not normative.

### 11. Security considerations [#11-security-considerations]

#### 11.1 Request forgery [#111-request-forgery]

An `https://` resolver attempts an arbitrary URL. Mitigations, all of which MUST be in place:

* an operator-configured allowlist of acceptable hosts;
* rejection of every scheme outside the normative list;
* **the resolver MUST NOT follow a redirect to a host outside the allowlist**;
* the fetch timeout of section 7.1.

#### 11.2 Plaintext exposure through placement choice [#112-plaintext-exposure-through-placement-choice]

A field marked public and placed externally has its plaintext uploaded unencrypted, and any read access to that store reads the plaintext. This is intended for genuinely public data and dangerous for accidentally public data.

Writers SHOULD warn when encoding a public field at a placement other than in-record, and deployments SHOULD be able to configure the combination as forbidden at encode time.

#### 11.3 Availability attack [#113-availability-attack]

A party that controls the store can withhold bytes to prevent replay. For external placement that means operator compromise or a hostile operator; for overlay placement it requires compromising every participant node. High-stakes deployments SHOULD therefore place critical fields on the overlay, monitor availability, and escalate unavailability of a critical field.

#### 11.4 URI enumeration [#114-uri-enumeration]

The URI for an audit or private field sits inside the outer wrap, so no observer sees it, but every party who can open that wrap sees every manifest on the records they receive. Where even an authorised audit-tier party should not learn URI metadata, for example because the URI embeds a semantic key name, operators SHOULD randomise the object key with a random 128-bit suffix. The manifest still anchors identity through the digest.

#### 11.5 Integrity binding is enforced by JOSE for encrypted fields [#115-integrity-binding-is-enforced-by-jose-for-encrypted-fields]

Because the reinstated JWE goes through the ordinary decryption step, a tampered ciphertext whose digest somehow matched a substituted value would still fail the AES-256-GCM authentication tag. An attacker would need to produce a ciphertext whose SHA-256 matches the manifest **and** whose tag verifies under the recipient's key.

For public fields there is no JWE, so integrity rests on SHA-256 alone and the collision resistance of that function is the sole guard.

#### 11.6 Size leakage [#116-size-leakage]

The manifest's size member reveals the exact size of the externalised bytes to every party that can open the outer wrap. For an encrypted field that is the ciphertext size, which reveals the plaintext size plus a constant overhead. Deployments that care SHOULD pad plaintexts to standard sizes **before** encryption; padding afterwards conceals nothing.

### 12. Examples [#12-examples]

**Mixed placement.**

```
hdr.fields = [
  { n: "photoHash",       sn: "pr", pl: "ch" },   // small, audit-critical
  { n: "confidenceScore", sn: "au", pl: "ch" },   // tiny, read by a partner
  { n: "photoBytes",      sn: "pr", pl: "ex" },   // multi-megabyte, operator store
  { n: "verificationMeta",sn: "au", pl: "ov" }    // shared among participants
]
```

Resulting slots:

```
pr[0] = { n: "photoHash",       jwe: <JWE> }
au[0] = { n: "confidenceScore", v: <score> }
pr[1] = { n: "photoBytes",      je: <JWE without ciphertext>,
                                im: { sha: <32 bytes>,
                                      u: "s3://bucket/<record>-photoBytes",
                                      sz: 2400000 } }
au[1] = { n: "verificationMeta",im: { sha: <32 bytes>,
                                      u: "overlay://<topic>/<hex digest>",
                                      sz: 1200 } }
```

**Fully overlay**, so that any participant running a node can resolve the field without depending on the originating participant being online:

```
hdr.fields = [
  { n: "maskedIdentifier", sn: "pr", pl: "ov" },
  { n: "sectorLabel",      sn: "pu", pl: "ch" }
]
```

**Public and external**, for a large publicly fetchable document:

```
hdr.fields = [
  { n: "policyTitle", sn: "pu", pl: "ch" },
  { n: "policyPDF",   sn: "pu", pl: "ex" }
]

pu[1] = { n: "policyPDF", im: { sha: <32 bytes>,
                                u: "https://policies.example/<id>.pdf",
                                sz: 3100000 } }
```

The reader fetches, verifies the digest and the size, and decodes the bytes.

### 13. Open questions [#13-open-questions]

* **Overlay cost model.** Replicated storage has a per-byte cost borne by every participant. For multi-megabyte values that grows quickly, and cost-sharing belongs in the deployment agreement rather than in this specification.
* **External URI authority.** An `https://` resolver fetches an arbitrary URL. Whether a writer should additionally sign the URI to prove operator authority over it is open for adversarial deployments. The client-derived case of section 4.1 addresses this partially, by binding the URI through derive-and-compare without a separate authority signature.
* **Automatic placement selection.** A deployment could declare a size threshold above which fields place externally. That is ergonomic and adds implicit behaviour; in this version the author declares placement explicitly.
* **The overlay authority component.** The topic identifier is currently the authority component of the URI. An alternative would name the node endpoint explicitly for targeted retrieval.
