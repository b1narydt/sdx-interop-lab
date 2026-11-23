<!-- tpnil:provenance-header -->
**TPNIL pinned source text.** SDX Protocol specification v0.1, dated 2026-07-17, revised 2026-09-01; keys, envelope and anchoring ratified 2026-09-01. This file holds the page *Test vectors*, the test-vector page published with the revision of 2026-09-01. Requirement citations use the clause prefix `VEC`.

- Source page: <https://sdxprotocol.org/protocols/data-sharing/v0.1/vectors/>
- Retrieved from: <https://sdxprotocol.org/llms.mdx/protocols/data-sharing/v0.1/vectors.md>, the site's Markdown rendition of the source page
- Retrieved at: 2026-11-11T05:08:32Z
- SHA-256 of the retrieved bytes: `559fcbeaa596de824aab42bc1167c5efab47e6d9427d403a3e738c3787638907`
- Licence: SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. [Reference copy](../../../../../LICENSES/SDX-Specification-License-1.0.reference.txt)
- Modification: none. The retrieved bytes follow the closing marker of this header unchanged; TPNIL added only this header. Root-relative links in the text resolve against `https://sdxprotocol.org`.

Attribution: SDX Protocol specification, version 0.1 (2026-07-17, revised 2026-09-01). The source page is the canonical publication. This copy retains the SDX licence terms and is excluded from TPNIL's Apache-2.0 grant; see the [third-party notices](../../../../../THIRD_PARTY_NOTICES.md).
<!-- tpnil:upstream-text-follows -->
# Test vectors (/protocols/data-sharing/v0.1/vectors)



> Normative. Reflects the specification as ratified on 1 September 2026. Version pinning is by date. Where this text and a published test vector disagree, the vector wins and the text is corrected.

Two suites are published for v0.1. Each is a single JSON file with a `profile` name, a `spec` paragraph stating the rule it pins, and a `vectors` array. Bytes are hex-encoded. The vector bytes are identical to the internal suite the reference implementation is tested against.

| Suite                       | Vectors | What it pins                                                                                                                                                                                                                                                                                               | File                                                                      |
| --------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `cbor-det-v1`               | 36      | The deterministic encoding profile of [The record envelope](/protocols/data-sharing/v0.1/envelope): map keys ordered by their encoded bytes, shortest-form integer heads, the refusal of integer inputs beyond the 53-bit safe range, and the erasure of type distinctions the encoding does not preserve. | [cbor-det-v1.json](/vectors/cbor-det-v1.json)                             |
| `historical-float64-decode` | 8       | Decode tolerance. Byte strings the reference encoder produced before the integer-widening rule, when an integer needing an 8-byte head was written as a float64. Records anchored under that encoder are immutable, so a conforming decoder MUST still read them back to the integer shown.                | [historical-float64-decode.json](/vectors/historical-float64-decode.json) |

## Vector shape [#vector-shape]

In `cbor-det-v1` each vector carries `name`, `doc` (the rule it exercises, with its RFC 8949 reference where one applies), `input` (a `kind` and a `value`) and `encoded_hex`, the exact bytes a conforming encoder MUST produce.

In `historical-float64-decode` each vector carries `name`, `doc`, `historical_hex` (the bytes as written by the pre-widening encoder) and `decodes_to`, the integer a conforming decoder MUST return. The suite was captured on 2026-08-11 from two independent sources agreeing byte for byte.

## How to validate an implementation [#how-to-validate-an-implementation]

1. Fetch the suite and turn each `input` into your native value.
2. Encode it under the deterministic profile.
3. Compare the hex of your bytes with `encoded_hex`. Any difference is a conformance failure on that vector; the profile has no tolerance on the encode side.
4. For the historical suite, decode `historical_hex` and compare with `decodes_to`. A decoder that refuses these bytes fails the suite.

## Suites named in Section 6 but not yet published [#suites-named-in-section-6-but-not-yet-published]

`docv2-envelope`, `dual-curve`, `placement`, `utxo-chaining`, `overlay-binding` and `cross-domain-refs` are named in [Section 6 of the specification](/protocols/data-sharing/v0.1) and follow alongside the reference implementation, at this address. Until each is published, the normative sections fix the shape an implementation must match.
