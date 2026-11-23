# Third-party materials and licensing limits

Original TPNIL materials use [Apache-2.0](LICENSE). The following materials retain their own terms and are excluded from that grant, except the attributed contributions identified as Apache-2.0 material. Their inclusion or use does not establish vendor participation or endorsement.

## Retained Open BSV materials — not relicensed

| Material | Provenance and applicable terms |
| --- | --- |
| `fixtures/standards/brc-167/chirp-v1.json` | Imported from `bsv-blockchain/ts-stack` at `f999e0c1aad9a7afd0cbadaaf23841d049af9d5a`; [manifest](fixtures/standards/manifest.json), Open BSV License Version 6 |
| `fixtures/standards/brc-170/conformance-vectors.json` | Imported from `bsv-blockchain/BRCs` at `9c9b3ecfe1c0b765400812deff57d018a01cf0ec`; [manifest](fixtures/standards/manifest.json), Open BSV License Version 6 |
| `synthesis/src/lch-reference/` and `synthesis/test/lch-reference.test.ts` | Adapted from the pinned ts-stack LCH reference application; [notices](synthesis/THIRD_PARTY_NOTICES.md) and [unchanged license](synthesis/LICENSES/ts-stack-lch-reference.txt) |

The [retained reference license](LICENSES/Open-BSV-License-6.reference.txt) limits use of the covered software and derivatives to BSV. TPNIL's Apache grant cannot remove those restrictions. These imports require a compatible upstream grant or independent replacement before they can be offered without those restrictions. Running the imported standards suites or synthesis profile remains subject to the applicable upstream terms.

## SDX Protocol specification materials — SDX licence retained

| Material | Provenance and applicable terms |
| --- | --- |
| `fixtures/sdx/v1/standards/text/` | Unmodified Markdown renditions of the SDX Protocol specification v0.1 pages (base specification, keys, envelope, anchoring and test vectors) and of the SDX licence page, retrieved from sdxprotocol.org on 2026-11-11 (UTC), each below a TPNIL provenance header; [index](fixtures/sdx/v1/standards/text/index.json). SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. |
| `fixtures/sdx/v1/standards/cbor-det-v1/` | The published SDX test-vector suites `cbor-det-v1` and `historical-float64-decode` from <https://sdxprotocol.org/protocols/data-sharing/v0.1/vectors/>, imported unchanged and pinned by the [SDX fixture manifest](fixtures/sdx/v1/manifest.json); same licence |

The [licence reference](LICENSES/SDX-Specification-License-1.0.reference.txt) permits anyone to copy, publish and redistribute the specification texts, in whole or in part, provided attribution to the SDX Protocol specification and its version date is preserved, and permits the published test-vector suites to be used and redistributed freely for implementing and verifying conformance. Modified versions must be clearly labelled as modified and must not be presented as the SDX Protocol specification. The licence conveys no rights to the SDX Protocol name or marks, and it assigns conformance claims to a separate SDX certification programme. TPNIL retains these materials unmodified with their attribution and edition dates; its Apache grant does not extend to them. The SDX reference implementation is licensed separately under the Business Source License 1.1 and is not included.

## Attributed contributions under Apache-2.0

`fixtures/sdx/v1/standards/draft-statements/` holds draft statements contributed by Binary Distributed Technologies Inc.: two BRC drafts ([index](fixtures/sdx/v1/standards/draft-statements/index.json)). They are contributed under Apache-2.0 in accordance with [CONTRIBUTING.md](CONTRIBUTING.md), keep their contributor's attribution, and are retained unchanged apart from removed front matter and links rendered as plain text. They are not TPNIL statements and have not been adopted by the SDX working group or by any standards body. SDX text they quote keeps the SDX licence.

## Dependencies and external software

Resolved npm dependencies, container images, operating systems, native applications and referenced standards retain their respective licenses. `synthesis/package-lock.json` pins npm artifacts; license text in each resolved artifact controls. The pinned `@bsv/sdk`, `@bsv/chirp`, `@bsv/lch`, `@bsv/wallet-toolbox`, authentication middleware and payment middleware artifacts each carry Open BSV License Version 6; see the [synthesis notices](synthesis/THIRD_PARTY_NOTICES.md). This migration supplies no new permissions for those packages, Teranode, Arcade, Merkle Service or other external components. A dependency reference or download script does not relicense its target.

The synthesis package includes both original Apache-licensed material and the Open BSV imports above. Its package metadata points to these notices rather than representing the whole package as unrestricted Apache material.

## Submitted artifacts and retained evidence

`fixtures/artifacts/` contains compiled third-party application material with its own provenance. Software identified in `suts/`, raw third-party content retained under `journals/`, and referenced or archived binaries keep their original terms. Original TPNIL report prose and evaluation tooling use Apache-2.0; embedded third-party content does not acquire that license.

Existing evaluation alone does not establish acceptance of submission terms. P2PPSR's owner has expressly accepted version 2.1.0 for the archived Metanet Explorer v1.1.10 AAB; see the [acceptance record](journals/submission-acceptance/2026-11-02/metanet-explorer-1.1.10/acceptance.json) and current intake evidence. The owner's [scope clarification](journals/submission-acceptance/2026-11-02/metanet-explorer-1.1.10/education-scope-clarification.json) adds broad non-commercial TPNIL-related use, including education. These records do not cover other releases or other vendors. Vendor participation announcements and continued hosting require the applicable license or an authorized acceptance covering the identified artifacts. Outstanding rights remain unresolved until supported; public availability alone supplies no additional grant. Public-result admission requires everyone's continuing rights to run, retain and mirror the artifacts for non-commercial TPNIL-related activity, including reproduction and education, plus an accessible reproduction bundle. This submission grant excludes resale and unrelated use or distribution, without narrowing broader rights available under an existing license. Existing binary archives and historical evaluations are not automatically cleared by adopting the submission terms.

Historical source-revision identifiers in retained evidence refer to the prelaunch development revisions recorded at execution. Replacing Git history does not change those observations or imply that historical workspaces used the current license.

## Optional Go controlled-service dependencies

The optional ITCVE Go host links the exact Go Overlay Services, Go ChainTracks,
Go SDK and Go Wallet Toolbox modules resolved by `synthesis/go/go.mod` and
`go.sum`. The three service source revisions and module checksums are recorded
in [the component lock](synthesis/go/components.lock.json). The three pinned service modules carry Open BSV License Version 5; their
unchanged license texts remain in the resolved module archives; linking or downloading them supplies no additional rights.
The digest-pinned MongoDB container used for component qualification retains
its own license. Original laboratory host and adapter code remains Apache-2.0.

## Integrated service and Rust dependencies

`integrations/services/vendor/` retains selected ChainTracks routes (Open BSV v6)
and Identity Services (Open BSV v4) at the per-file hashes and source revisions
in `integrations/services/sources.json`, with unchanged upstream licenses.
Additional npm closures are fixed by `integrations/services/package-lock.json`
and `components/transport/package-lock.json`. Message Box preparation downloads
the exact sources in `components/messaging/sources.lock.json`; upstream licenses
remain controlling. The Rust participant links the SDK revision and dependencies
fixed by `components/rust/Cargo.lock`. These pins and compatibility patches grant
no new rights and imply no vendor endorsement.

## SDX vector generator dependencies

The SDX vector generators under `components/sdx/` are laboratory tooling. The SDX checkers in `src/sdx/` and `src/portability/brc39-recipient.mjs` and the SDX tests use only Node.js built-in modules or the Python standard library. Each generator's npm closure is fixed by its lockfile; the resolved packages are installed from the registry and are not stored in the repository.

| Lockfile | Resolved packages and licenses |
| --- | --- |
| `components/sdx/b39r/package-lock.json` | `@bsv/sdk` 4.0.1 (Open BSV License Version 6), `@noble/ciphers` 2.4.0 (MIT) |
| `components/sdx/proof/package-lock.json` | `@bsv/sdk` 4.0.1 (Open BSV License Version 6), `cborg` 6.2.1 (Apache-2.0) |
| `components/sdx/p256/package-lock.json` | `@bsv/sdk` 4.0.1 (Open BSV License Version 6), `@noble/curves` 2.4.0 (MIT), `@noble/hashes` 2.4.0 (MIT), `cborg` 6.1.3 (Apache-2.0), `jose` 5.10.0 (MIT) |
| `components/sdx/envelope/package-lock.json` | `@noble/ciphers` 2.4.0 (MIT), `@noble/curves` 2.4.0 (MIT), `@noble/hashes` 2.4.0 (MIT), `cborg` 6.2.1 (Apache-2.0), `jose` 6.2.17 (MIT), `lzma` 2.3.2 (LZMA-JS, MIT) |
| `components/sdx/key/package-lock.json` | `@bsv/sdk` 4.0.1 (Open BSV License Version 6), `@noble/curves` 2.4.0 (MIT), `@noble/hashes` 2.4.0 (MIT) |
| `components/sdx/admission/package-lock.json` | `@bsv/sdk` 4.0.1 (Open BSV License Version 6), `@noble/curves` 2.4.0 (MIT), `@noble/hashes` 2.4.0 (MIT), `cborg` 6.2.1 (Apache-2.0) |

The P-256 search tool's `components/sdx/p256/grind/go.mod` declares no module dependencies; the tool uses the Go standard library. License text in each resolved artifact controls. The license distributed with `@bsv/sdk` 4.0.1 is identical to the [retained Open BSV reference](LICENSES/Open-BSV-License-6.reference.txt), and running that package remains subject to it. The optional Rust cross-check of the proof suites uses the participant fixed by `components/rust/Cargo.lock`. These pins grant no new rights and imply no vendor endorsement.
