<!-- tpnil:draft-statement-header -->
**Draft statement.** Contributed by Binary Distributed Technologies Inc., dated 2026-11-18. It has not been adopted by the SDX working group or by any standards body, and its text is not TPNIL's. TPNIL retains it unchanged as attributed contributed material under Apache-2.0 ([CONTRIBUTING](../../../../../CONTRIBUTING.md)). Format changes only: the source's YAML front matter was removed, and links to package documents not reproduced in this directory are shown as plain text.
<!-- tpnil:draft-statement-text-follows -->
# BRC draft: SDX account keys on both curves as a BRC-98 module

**Status:**
- Draft from Binary, 2026-11-10, revised 2026-11-12, 2026-11-15, 2026-11-16 and 2026-11-18. Not yet submitted.
- Revision of 2026-11-12: the module now holds SDX accounts and serves both of their key trees. It was `p256`, a P-256-only module that relied on a separate wallet instance per account for the secp256k1 keys. BRC-100 has no way for an application to select such an instance, so the module now selects the account itself and also answers the secp256k1 operations SDX needs. The scheme is renamed `sdx`.
- Revision of 2026-11-15: the module keeps only what SDX v0.1 needs. `unwrap` and `link` are removed, and so are derivations under the rotation namespace and per-grant delegation keys. The module now separates the namespaces in both directions and validates every key path against the deployment profile at the derivation boundary.
- Revision of 2026-11-16: adds `k1ring`, an admission proof for a topic whose business rule admits only records from a roster of account roots (ANC §11.1, §11.2). The proof shows that the key signing one input of a record's transaction derives from a root on the roster, without showing which root. SDX v0.1 does not need it, and it changes no v0.1 verdict.
- Second revision of 2026-11-16: `k1ring` proves with Curve Trees (proof type `ct-secp256k1-v1`) and no longer with a Groth–Kohlweiss ring proof. `ring` is the roster's leaf list in order, with empty slots, up to 16,777,216 slots. The wallet builds the tree from it, and returns the whole admission value. A proof's cost no longer grows with the roster.
- Revision of 2026-11-18: no change to any request or result. The text now matches a roster that publishes only its root bytes and keeps its member list private, and a transaction that carries no record but still carries an admission proof. It states that the module owns authorization, as BRC-206 and BRC-116 require of a P-module, and corrects citations of BRC-39, BRC-206, BRC-208, BRC-250 and SDX ENV §3 and §8.7.
- Second revision of 2026-11-18: successful requests and their results are unchanged. A wallet now authorizes a request before it reads which accounts, epochs and roots it holds. So it refuses an unauthorized request in the same way whether or not it holds the account, and derives and draws nothing for it (Permissions, Errors). The trusted UI says when a derived key is publicly linked to its root. A session is found with the profile's session keyword. The wallet refuses a grant prefix that does not end at a boundary. The backup rule names only what the wallet holds. New sections: Relationship to BRC-98, Errors, Conformance vectors and References.
- It would go through the BRC process (drafts README). It needs no change to SDX v0.1.
- It follows the pattern of BRC-229 (`p ecpm`) and BRC-206 (`p rabin`).
- Draft conformance vectors exist, with independent checkers, and a reference module replays every executable case (Conformance vectors). None is published yet.

## Abstract

This draft defines `sdx`, a [BRC-98](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0098.md) module scheme. It lets a BRC-100 wallet hold SDX v0.1 accounts and serve everything SDX needs from both of an account's key trees, while no application ever holds a key:
- hold one or more SDX accounts, each a 64-byte root split exactly as SDX v0.1 splits it (KEYS §1.4.2), and the wallet's own actor root;
- on secp256k1: return derived public keys, and sign audit-layer transactions: spending a chain's tip, and spending handoff and top-up outputs;
- on secp256k1, for a topic that admits only records from a roster of account roots: prove that the key that will sign a record's transaction derives from one of those roots, without showing which;
- on P-256: return public keys and recipient key identifiers, produce ES256 signatures, and decrypt `ECDH-ES+A256KW` JWE entries with a JOSE implementation.

Every request is carried on the existing `encrypt` method, except `decrypt` requests, which are carried on `decrypt`. No BRC-100 method, call code, Wallet Wire message or optional member is added. A wallet that does not install the module rejects the reserved protocol, as BRC-98 requires.

## Motivation

- **SDX needs both curves from one root.** An SDX account's secp256k1 seed signs its audit-layer transactions, and its P-256 seed signs its envelopes and addresses its recipients (KEYS §1.5). Both seeds come from one 64-byte root (KEYS §1.4.2).
- **BRC-100 cannot reach an account's keys.** A BRC-100 wallet derives every key from one root, the key behind its identity key. An SDX account's keys come from the account's own root. BRC-100 never returns a private key to derive from, and it has no parameter that selects a different root. A module inside the wallet can hold the account roots and answer for both curves.
- **P-256 is the NIST general-purpose curve** used by JOSE (ES256), passkeys, phone secure enclaves, EU identity wallets and SDX v0.1. SDX v0.1 signs records with ES256 and wraps field keys to P-256 recipients (`ECDH-ES+A256KW`). BRC-100 wallets are secp256k1 only.
- **Only `encrypt` and `decrypt` carry arbitrary bytes through every BRC-100 substrate** (BRC-206 §Motivation). A `getPublicKey` result must be a 33-byte secp256k1 point, and a `createSignature` result DER of at most 72 bytes. An ES256 signature is 64 bytes `r ‖ s`, and a P-256 key is not a secp256k1 point.
- **With this module the account keys live in the wallet.** They come from roots the wallet derives from its own root, so the wallet's existing backup and the account list recover them. They are reached through standard calls. The module authorizes each request itself, through the wallet's trusted UI (Permissions).

## Relationship to BRC-98

BRC-98 reserves protocol IDs that begin with `p `. A wallet rejects them unless it supports the scheme they name, and a scheme it supports applies its own rules. This draft uses that reserved dispatch point to give two existing BRC-100 methods, `encrypt` and `decrypt`, a specific meaning under `p sdx`. It does not amend BRC-98, BRC-2 or BRC-100.

The boundary is safe for compatibility:
1. Outside `p sdx`, `encrypt` and `decrypt` keep their BRC-2 meaning.
2. Under `p sdx`, a wallet either implements this module or rejects the request, as BRC-98 requires.
3. The `ciphertext` that `encrypt` returns under `p sdx` is a public key, a signature or an admission value. It is not BRC-2 ciphertext, and MUST NOT be passed to `decrypt` as BRC-2 ciphertext.
4. `decrypt` under `p sdx` takes a CBOR input that carries one JWE entry, not BRC-2 ciphertext. It is rejected with any operation other than `decrypt`.
5. No optional member is added to any BRC-100 method, so no application infers support from one. A wallet without the module rejects the request (item 2).

## Specification

### Scheme, operations and carrier methods

The scheme ID is `sdx`. The protocol name is:

```
p sdx <operation> <role> <h>
```

`<role> <h>` is the logical protocol ID: the rest of the BRC-98 protocol identifier, as BRC-206 and BRC-229 call it. It names the root a request uses (Roots and selection, below):
- `<h>` is the account tag: the 32-character lowercase hex of the first 16 bytes of SHA-256(UTF-8 account ID). Base58 account IDs contain uppercase letters, so they never enter a protocol name.
- `<role>` is one of `write`, `read`, `root`, `actor` and `session`.

| Operation | Curve | Carrier method | Input | Result |
|---|---|---|---|---|
| `open` | both | `encrypt` | `plaintext` = CBOR `{acct, ep?}` | `ciphertext` = 66 bytes: `R ‖ K`, the account's P-256 root public key `R = p256_seed·G` and secp256k1 root public key `K = secp256k1_seed·G` for that epoch, each compressed. Creates the account, or the epoch, if the wallet does not hold it (Roots and selection) |
| `key` | P-256 | `encrypt` | `plaintext` = CBOR `{path?, peer?, ep?}` | `ciphertext` = the own derived P-256 public key (33 bytes, compressed). When `path` is absent, it is `R`, with no derivation |
| `peer` | P-256 | `encrypt` | `plaintext` = CBOR `{path, peer, ep?}` | `ciphertext` = the peer's derived P-256 public key (33 bytes). For SDX this is the `kid` a writer addresses |
| `sign` | P-256 | `encrypt` | `plaintext` = CBOR `{path, peer?, msg, ep?}` | `ciphertext` = ES256 signature `r ‖ s` (64 bytes) over `SHA-256(msg)`, low-S (step 4) |
| `decrypt` | P-256 | `decrypt` | `ciphertext` = CBOR `{path, peer, jwe, ep?}` | `plaintext` = the JWE's plaintext. The wallet decrypts one `ECDH-ES+A256KW` entry with `A256GCM` content using a JOSE implementation (SDX ENV §16), with the own P-256 child key for `path` and `peer` as the one candidate key (ENV §5.3). The content-encryption key never leaves the wallet |
| `k1key` | secp256k1 | `encrypt` | `plaintext` = CBOR `{path?, peer?, ep?}` | `ciphertext` = the own derived secp256k1 public key (33 bytes, compressed). When `path` is absent, it is `K`, with no derivation |
| `k1peer` | secp256k1 | `encrypt` | `plaintext` = CBOR `{path, peer, ep?}` | `ciphertext` = the peer's derived secp256k1 public key (33 bytes). For SDX this is the lock of a handoff output addressed to the peer |
| `k1sign` | secp256k1 | `encrypt` | `plaintext` = CBOR `{path, peer?, hash, ep?}` | `ciphertext` = a DER ECDSA signature over the 32 bytes of `hash` as given, low-S (step 4). For an audit-layer transaction, `hash` is the signature hash of the input being signed |
| `k1ring` | secp256k1 | `encrypt` | `plaintext` = CBOR `{path, H, topic, ring, outpoint, ep?}` | `ciphertext` = CBOR `{t, H, rosterHash, vin, proof}`, the admission value: a proof of type `ct-secp256k1-v1` that Q, the own derived secp256k1 key for `path`, derives from one of the member roots in `ring`, without showing which. Every proof is 2,834 bytes. Roles `write` and `root` only (Admission proofs) |

- **CBOR inputs.** These are CBOR maps in SDX's deterministic encoding (ENV §3). A wallet MUST reject an input that does not re-encode to the same bytes, or that carries an unknown member. This is stricter than ENV §3 asks of a decoder, which may accept a non-shortest integer head. An input is a request, never a stored record, so strictness costs nothing, and each input has one encoding.
  - `acct` is a text string: the account ID as SDX KEYS §1.6.2 writes it.
  - `ep` is an unsigned integer: the epoch whose root is used. When absent, the account's current epoch is used. An epoch becomes current when `open` creates it, and the wallet's own interface may make another held epoch current.
  - `path` is a text string: the full derivation identifier `<securityLevel>-<namespace>-<keyPath>` of SDX KEYS §1.8.1. Its namespace MUST be one the deployment's profile registers with a role on the operation's curve (KEYS §1.7), and its key path MUST pass the key-path rules below. Its key path is ENV §8.5–§8.6's key path for record keys, ANC §3.1's for a chain's commitment keys, KEYS §1.6.1's for handoff and top-up outputs, KEYS §2.14.2's for session keys, or step 1's for the actor's persistent key.
  - `path` is used byte for byte, with no Unicode normalisation. KEYS §1.12 item 8 requires a field name to reach its composed form before hashing, and does not say which layer normalises. Here the producer normalises field names to NFC (KEYS §1.6.2) before it builds the path, and the module hashes the bytes it is given: VC-P256 case `key-path-nfd` derives a different key from the decomposed name.
  - `peer` is a 33-byte compressed point on the operation's curve: P-256 for `key`, `peer`, `sign` and `decrypt`, and secp256k1 for `k1key`, `k1peer` and `k1sign`. When absent, it means the root's own public key (`self`). `k1ring` takes no `peer`.
  - `peer` may be the curve's generator G, which is BRC-100's counterparty `anyone`. Then `S` (step 3) is the root's public key, so anyone who knows that key can compute the offset and link the child key to the root. SDX uses this only where that link is meant to be public: a roster request and a discovery document (How SDX uses it). The trusted UI says so (Permissions).
  - `msg` is the byte string ES256 signs. `hash` is exactly 32 bytes.
  - `H`, `topic`, `ring` and `outpoint` are `k1ring`'s inputs (Admission proofs):
    - `H` is an unsigned integer: the block height whose roster the proof uses.
    - `topic` is a non-empty text string: the name of the topic that requires the proof.
    - `ring` is a byte string: the roster's leaf list, in the topic's leaf order, as 33-byte entries concatenated. Each entry is a member root, a compressed secp256k1 point, or 33 zero bytes for an empty slot. A root may appear more than once. It holds 1 to 16,777,216 entries (64⁴, the tree's capacity).
    - `outpoint` is 36 bytes: the txid of the output that the sealing input spends, in internal byte order, then that output's index as four little-endian bytes.
    - For `k1ring`, `path` names the key Q that will sign the sealing input. That is the chain tip's commitment key (ANC §3.1, §4.2). For a chain's first record, which spends a funding entry (ANC §4.1), it is a top-up key, `…/action/<actionId>/topup/<n>` (KEYS §1.6.1), that locks the funding input.
  - `jwe` is one recipient's flattened JWE serialization (RFC 7516 §7.2.2) as a CBOR map, with the JSON member names and text values an SDX envelope carries: `protected`, `header`, `encrypted_key`, `iv`, `ciphertext`, `tag` and optionally `aad`. A reader builds it from a general JWE by taking the shared members and its own entry of `recipients`. `header` holds only `alg`, `kid`, `epk`, `apu` and `apv`. Each member is in `header` or in the protected header, never both: a JOSE implementation writes `epk` in the protected header when a JWE has one recipient. The joint header's `alg` MUST be `ECDH-ES+A256KW`. The wallet rejects any other member, and validates `epk` as a P-256 point (Point validation) before it uses a key.
- **The deployment profile.** The module takes the profile's per-curve labels, namespaces, key-path keywords and level-4 purposes as one constant, derives with it and validates with it. It checks the constant against KEYS §1.3 and §1.6 when the wallet loads it, not at first use (KEYS §1.11.4, §1.12 item 11).
- **Namespace separation.** KEYS §1.7 forbids using a key derived for one role for the purpose of another, and KEYS §1.11.2 makes implementations enforce it, because the derivation function does not. A wallet therefore:
  - MUST reject a `decrypt` whose `path` is outside the profile's encryption namespace;
  - MUST reject a `sign` or `k1sign` whose `path` is in the encryption namespace. Both take keys from the signing-role namespaces of KEYS §1.7's table: `sign` from the signing and delegation namespaces, and `k1sign` also from the handoff namespace, for spending handoff outputs, and from the transport-authentication namespace. Top-up outputs are under the signing namespace (KEYS §1.6.1);
  - MUST reject a `k1ring` whose `path` is outside the signing namespace. Commitment keys and top-up keys are both under it (ANC §3.1, KEYS §1.6.1);
  - MUST NOT derive under the rotation namespace. KEYS §1.7 reserves it, and a deployment whose rotation records sign under the signing namespace derives nothing under it. KEYS §1.10.3 step 5 binds both rotation signatures to keys under the signing namespace, so a rotation needs no namespace of its own: `open` creates the new epoch, and `sign`, `k1key` and `k1sign` with `ep` serve both roots.
- **Key paths.** The module checks every key path at the derivation boundary, from the same profile constant it derives with (KEYS §1.6.1, §1.11.4, §1.12 item 10):
  - A key path is 1 to 1,033 bytes (KEYS §1.3).
  - For roles `write`, `read`, `root` and `session`, it follows KEYS §1.6.1 with the profile's keywords: `account/<accountId>`, then `runtime/<runtimeId>`, then at level 3 `action/<actionId>` or `session/<sessionId>`. Only `action` has a level 4, `<purpose>/<id>`, and `<purpose>` MUST be one the profile registers. Shorter prefixes are higher levels. No segment is empty.
  - The module rejects KEYS §1.6.1's delegation variant, `…/delegation/<delId>/actor/<actorPubKey>`. Its actor side derives from the actor's grant-pinned key, which is not a root the module holds. KEYS §2.14.1 keeps it off the dispatch path ("No derivation happens at verification time").
  - For role `actor`, the only key path is the actor's persistent key path, `actor/<index>` under the delegation namespace (step 1), with `<index>` a decimal number with no leading zero.
  - For `k1ring`, the key path MUST be an `action` path at level 3, `…/action/<actionId>`, or at level 4, `…/action/<actionId>/<purpose>/<id>` with a registered purpose. An account, runtime or session path is refused.
- **Other methods.** A conforming wallet MUST reject:
  - every other BRC-100 method under `p sdx`;
  - `encrypt` with `decrypt`, or with an unknown operation;
  - `decrypt` with any other operation;
  - `p sdx` baskets and labels.
- **BRC-100 fields.**
  - `privilegedReason`, `seekPermission` and `originator` keep their BRC-100 meanings, as in BRC-229. `privileged: true` is rejected (Path scoping, below).
  - The root is selected by the logical protocol ID, so `keyID` and `counterparty` select nothing. A wallet MUST reject any `counterparty` other than `self`, and shows `keyID` only in prompts.
  - Counterparties travel in the CBOR input as `peer`, because a BRC-100 `counterparty` is a secp256k1 identity key that the wallet's own root would derive against.

### Roots and selection

The module holds every root the wallet keeps for SDX, and selects one for each request.

- **Account roots.** For each SDX account the wallet holds, and for each of its epochs, the module keeps that epoch's 64-byte root keying material `ikm` (KEYS §1.4.1), or its two per-curve seeds (KEYS §1.4.4). The account list (Account list and recovery) records them.
- **Selection.** For roles `write`, `read` and `root`, the module uses the account whose tag is `<h>`, at epoch `ep`. Once the request is authorized (Permissions), it rejects a request whose `<h>` names no account it holds, or whose `ep` names no epoch of that account. The three roles select the same root; they differ only in the permissions a wallet attaches to them (Permissions).
- **Actor and session roots.** For role `actor`, the module uses the wallet's actor root, and for role `session` the session root for the `<sessionId>` that follows the profile's session keyword in `path` (Actor wallets, in step 1 below). For these roles `<h>` names the account the actor acts for and scopes grants, and does not select the root. A request with role `actor` or `session` that carries `ep` is rejected, and so is a request with role `session` whose `path` is absent or names no session. These two checks read only the request, so they come before any prompt. The wallet derives the actor root, or draws a session root, only for an authorized request.
- **`open`.** `open` requires role `root`, and `<h>` MUST be the tag of `acct`; a mismatch is rejected before any prompt.
  - When the wallet holds the account at `ep`, `open` returns its root public keys.
  - Otherwise it creates the account, or a new epoch of it, from the wallet's own root (step 1). This always prompts, even under a standing grant for `open` (Permissions). A new epoch is a rotation's new root (KEYS §1.10.2). It becomes the current epoch once it is opened, and older epochs stay available for replay.
  - Epochs start at 0 and go up by one at each rotation (KEYS §1.10.1, §1.10.6). A new account is created at epoch 0, and a new epoch only as the one after the highest epoch the wallet holds for that account. Any other `ep` that names no held epoch is rejected. Such a request would create, so the wallet prompts first and refuses it only once the user approves; until then it shows nothing of which epochs it holds (Permissions). An imported account may start at any epoch.
  - The application chooses the account ID. KEYS §1.6.2 requires it to be random.
  - The wallet rejects an `acct` whose tag equals the tag of a different account it holds. It checks this, too, only after the prompt.
- **`k1ring`** requires role `write` or `root`. It proves for the account root that the request selects, at `ep` or at the current epoch, and never for the actor root or a session root.
- **Imported accounts** come in through the wallet's own interface, never through an application request, because an application that passed an `ikm` in a request would have held it.
- **Which wallet root.** In a wallet that keeps several accounts under one vault master (BRC-208), an SDX account belongs to one of those accounts, and step 1's wallet root is that account's root as BRC-208 derives it. Under BRC-208's `self-child` derivation, account 0's root is the root key itself; under its BRC-157 derivation, no account root is the master. Restoring the master recovers the BRC-208 accounts, and each one's SDX accounts follow from its account list.
- **One writer at a time.** An SDX chain has one write in flight, and a writer that sees two spendable tips must halt (ANC §4.2). A wallet installed on several devices MUST therefore run `sign`, `k1sign`, and `open` when it creates, only on the install that holds the account under BRC-249 (a draft with a proposed number). `key`, `k1key`, `peer`, `k1peer`, `decrypt` and `k1ring` may run on any install. `k1ring` only proves and spends nothing; the seal that uses its proof is a `k1sign`, which runs on the holding install.

### Canonical derivation: one root for both curves

Both of an account's key trees come from the same root, split exactly as SDX v0.1 splits it (KEYS §1.4).

1. **Root keying material.** The module works from 64 bytes of root keying material, `ikm`, per account and epoch. This is what SDX requires of every runtime (KEYS §1.4.1).
   - **Accounts created in the wallet.** The `ikm` MUST be derived inside the wallet from the wallet's own root, exactly as follows, so that a wallet restored into a different BRC-100 wallet yields the same accounts:

     ```
     d   = the BRC-42 child private key for
             protocolID   [2, "admin sdx root"]
             keyID        "<accountId> <epoch>"
             counterparty self
     ikm = HKDF-SHA-256(IKM  = d as a 32-byte big-endian integer,
                        salt = UTF-8("p sdx v1"),
                        info = UTF-8("sdx root"),
                        L    = 64)
     ```

     - `<accountId>` is the account ID as SDX KEYS §1.6.2 writes it, and `<epoch>` is the decimal epoch number.
     - This follows BRC-206's canonical seed derivation. `d` is obtained through private-key derivation, never from a BRC-2 symmetric key or an HMAC key. It is used only as HKDF input, and is never used as a key or returned.
     - The `admin` prefix reserves the protocol to the wallet, so no application can request it (BRC-44).
     - KEYS §1.4.1 requires exactly 64 bytes, and names a mnemonic-derived seed, a passphrase stretched with PBKDF2, and a hardware or cloud key service as sources an implementation MAY use. This construction is a further source of the same kind: a key service that is the wallet itself. The split of step 2 then runs unchanged.
     - A threshold wallet runs this step and the split of step 2 as one joint computation, so `d`, `ikm` and the seeds never exist in one place (Threshold wallets, below).
   - **Imported accounts.** An account moved in from another implementation brings its own `ikm` (KEYS §1.4.1), or its two per-curve seeds (KEYS §1.4.4). The wallet marks it as imported in its permission UI and backup.
   - **Actor wallets.** A person's or agent's wallet that acts for an SDX account (KEYS §2) is not that account, and holds its own 64-byte root for its actor keys.
     - It derives that root with the construction above, using the key ID `actor` in place of `"<accountId> <epoch>"`, and splits it as in step 2. The key ID cannot collide with an account's, which always contains a space. Requests with role `actor` use it.
     - **Persistent key.** Its persistent P-256 key is the child at `2-sdx delegate-actor/<index>` with counterparty `self`, where `<index>` is a decimal key index, starting at 0, that changes only when the actor replaces the key. The key is published in the actor's DID document's `assertionMethod` before any grant is issued, and grants pin it raw (KEYS §2.3, §2.10, §2.14.1). A delegate record signed with it carries it, so a verifier compares keys and derives nothing (KEYS §2.7.2, §2.14.1). SDX does not fix this path, so it is this draft's recommendation.
     - The persistent key is not part of any runtime's key tree. KEYS §1.6's grammar governs the key trees of accounts and their runtimes, so it does not apply to this path. The module accepts `actor/<index>` only with role `actor` and under the delegation namespace, and accepts nothing else with role `actor` (Key paths, above).
     - **Per-grant keys are not served.** KEYS §2.14.1 keeps the delegation path `account/<accountId>/runtime/<runtimeId>/delegation/<delId>/actor/<actorPubKey>` for flows where an actor anchors its own records and for mutual authentication, off the dispatch path. On the actor's side that derivation starts from the private key behind `actorPubKey`, the pinned key, which is a child of the actor root and not a root the module holds. A wallet that needs it can add an operation later.
     - In key paths, `sessionId` is the lowercase hex of its 16 bytes. This is an interpretation: KEYS §1.6.2 gives no text form for it (open item 15).
     - **Sessions.** For a short-lived session, the wallet itself follows KEYS §2.14.2, with one difference: the wallet keeps the session private keys. KEYS §2.14.2 step 5 hands them to the caller; here the caller gets public keys and signatures instead. The wallet draws a fresh 64-byte root and derives the session keys under `[2, "sdx delegate"]` at `account/<accountId>/runtime/<runtimeId>/session/<sessionId>`, counterparty `self`. Requests with role `session` use the session root for the `<sessionId>` their `path` names; the wallet draws it on first use and discards it when the session ends. The session keys therefore stay in the actor's wallet, and the runtime never holds them ("a runtime … MUST NOT custody actor keys").
   - **Threshold wallets.** A wallet whose root key is held in threshold shares derives an account's seeds without assembling the wallet root, `d`, `ikm` or either seed. It holds both seeds as threshold keys, as SDX KEYS §1.4.4 allows ("two pre-split per-curve seeds as independent managed keys").
     - **Shares of `d`.** The BRC-42 offset needs only the self shared point, which the holders compute by threshold ECDH. One holder adds the offset to its own share, so the holders' shares sum to `d`.
     - **The joint computation.** A secure two-party computation, such as a garbled circuit, takes the shares of `d`. It computes `ikm` as above, runs the split of step 2 with its range checks, and gives each holder fresh shares of `secp256k1_seed` and of `p256_seed`, and one public bit saying whether the seeds are valid. It never outputs `d`, `ikm` or a seed.
     - **Conformance.** The seeds are the ones step 2 gives for the `ikm` that the shares define, which is what KEYS §1.4.4 requires ("bit-identical results to §1.4.2"). Running the computation on the vectors' inputs and comparing public keys shows it, without revealing a seed.
     - **Cost.** About 17 SHA-256 compressions, once per account and epoch. A child key (step 3) adds the offset `h` to the seed. The holders compute `h` by threshold ECDH, and one holder adds it to its own share, so the module's operations need only threshold ECDH, and threshold ECDSA on each curve. The wallet never returns `h`: for a self-derivation it links a child key to its root, and it is the secret of an admission proof.
     - **Recovery and export.** Recovery restores the wallet's shares and the account list (Account list and recovery), then runs the computation again, which gives the same seeds. Exporting to an implementation that holds a whole root needs the holders to reconstruct `ikm` deliberately.
2. **The split** follows SDX KEYS §1.4.2 exactly:
   - `secp256k1_seed = HKDF-SHA-256(ikm, salt = "", info = <secp256k1 label>, L = 32)`;
   - `p256_seed = HKDF-SHA-256(ikm, salt = "", info = <P-256 label>, L = 32)`;
   - the labels are the deployment profile's, used byte for byte. SDX's example profile uses `sdx-secp256k1` and `sdx-p256`. They are bound to the account when it is created or imported.
   - Each seed MUST lie in `[1, n − 1]` for its curve. Otherwise the wallet aborts and reports the `ikm` as unusable. It never clamps the value into range (KEYS §1.4.3).
   - The P-256 root is `r = p256_seed`, and the secp256k1 root is `k = secp256k1_seed`.
3. **Child keys.** These use BRC-42's construction on each curve, with the root `x` (`r` on P-256, `k` on secp256k1) and that curve's order `n`:
   - `S` is the compressed encoding of `x·Q`, where `Q` is `peer`, or for `self` the root's own public key `x·G`;
   - `h = int(HMAC-SHA256(key = S, msg = UTF-8(path)))`, read big-endian. If `h` is 0 or `h ≥ n`, the derivation fails, and `h` is never reduced mod `n`. This is the draft's reading of KEYS §1.8.2, which contradicts itself: its pseudocode computes `int(hmac) mod N`, and its rejection rule then rejects a scalar `≥ N`, which the reduction makes unreachable. KEYS §1.12 item 7 requires a known-answer test in which a scalar equal to `N`, and one greater, each raise the typed rejection, and only the unreduced value can give that. On P-256 `h ≥ n` happens about once in 2^32 derivations, so the reading changes results at scale. On secp256k1 it happens about once in 2^128, so the results equal BRC-42 as wallets already implement it;
   - the own child private key is `(x + h) mod n`. If it is 0, the derivation fails;
   - the peer's child public key is `Q + h·G`.

   On secp256k1, SDX's derivation identifier is a BRC-43 invoice number (KEYS §1.8.1), so, for a key path within BRC-43's 800-byte key-ID limit, `k1key` with `path = "<s>-<namespace>-<keyPath>"` returns exactly what BRC-100 `getPublicKey` would return for protocol `[s, "<namespace>"]` and key ID `<keyPath>` in a wallet whose root is `k`. On P-256 the results MUST equal SDX KEYS §1.8 bit for bit. SDX's `dual-curve` vector suite is to confirm both (open item 1).
4. **Signatures.**
   - `sign` uses the own P-256 child key and returns `r ‖ s`, each 32 bytes big-endian.
   - `k1sign` uses the own secp256k1 child key, signs `hash` as given without hashing it again, and returns the DER encoding, as BRC-100 `createSignature` does. The caller appends the transaction's sighash flag.
   - Both use RFC 6979 deterministic nonces, and then canonicalise the signature to low-S. KEYS §1.8.3 says producers SHOULD produce low-S and verifiers SHOULD accept either form; the module MUST produce low-S, so that its output is deterministic. A threshold wallet generates the nonce jointly, as threshold ECDSA requires, so its signatures are valid but not reproducible, and are checked by verification instead of by comparing bytes.

**Result.** A wallet with this module derives the same keys from an account's `ikm` as any SDX v0.1 runtime holding that `ikm`, on both curves. The account is an ordinary v0.1 account, so no exception from v0.1 is needed.

### Admission proofs

`k1ring` serves a topic whose admission service runs a business rule (ANC §11.1): it admits a record only if the key that signs one input of the record's transaction derives from an account root on the topic's roster.
- The roster, the heights `H` a topic accepts, and where a record carries the proof are that topic's rule. SDX v0.1 defines none of them.
- Business rules only narrow what a topic admits (ANC §11.2). A plain v0.1 reader reads a gated record as it reads any other.
- Only the holder of the account root can make the proof, because it needs the offset of a self-derivation. The module makes it inside the wallet.

**The statement.** A key derived from an account root K at `path` is Q = K + h·G, where `h` is the offset of step 3 with counterparty `self` (KEYS §1.8.2, ANC §3.1). The roster's leaves are committed in a Curve Trees tree (Campanelli, Hall-Andersen and Kamp, USENIX Security 2023) on the secp256k1/secq256k1 cycle. The proof shows, without showing which leaf, that Q − K = h·G for a leaf K of the tree whose root the verifier holds:
1. It re-randomises the prover's leaf to K' = K + r·H, for a random r, where H is the secp256k1 blinding generator, and proves in zero knowledge that K' re-randomises a leaf of the tree.
2. A Schnorr proof on two bases shows knowledge of (h, s) with Q − K' = h·G + s·H. The honest prover has s = −r.
3. Two transcripts, one per curve, each labelled with its side, bind both parts to the proof type, the tree's shape, a digest of the root bytes, Q and the message. The digest is SHA-256 of the root bytes' length as 8 big-endian bytes, followed by the root bytes. The reference crate fixes this binding; an independent implementation needs it written down (open item 20).

Its cost depends on the tree's depth, not on the roster's size.

**The tree.** It has 64 children per node and depth 4: leaves on secp256k1, and levels that alternate with secq256k1 up to the root.
- Level 0 holds the leaves in `ring`'s order. A node commits, without blinding, to its children's x-coordinates, each taken of (child + Δ) for its curve's fixed point Δ.
- An empty slot holds 0, as does an unused slot past the end. So does a node with no member below it. No point on either curve has x = 0, so no proof can select such a slot.
- Trailing empty slots therefore leave the root unchanged.
- The root bytes are the x-coordinates of the root's 64 child slots, 32 bytes each, 2,048 bytes in all. They are all that a verifier needs of the tree.
- A roster that gives each new member the lowest free slot, and empties a removed member's slot in place, changes one node per level for each slot that changes (informative).

**What the wallet does,** in this order:
1. It checks the request as for any operation: the carrier, the role (`write` or `root`), and a deterministic CBOR input with the five required members, optionally `ep`, and their types.
2. It checks `path`: the signing namespace, and an `action` key path at level 3 or 4 (Key paths).
3. It checks `ring`'s shape, decoding no point. The length is a non-zero multiple of 33 bytes, and the count is at most 16,777,216 entries, or a lower bound the wallet sets. Each entry starts with 02 or 03, or is 33 zero bytes.
4. It applies permissions (Permissions).
5. It selects the account and the epoch (Roots and selection).
6. It finds the account's root K for that epoch in the ring: the first slot that holds it. Steps 5 and 6 come after permissions, so a caller without a grant or an approval cannot learn whether the wallet holds the account, or whether its root is in a ring the caller made up.
7. It computes `h` for `path` and Q = K + h·G (step 3). It refuses a ring that holds Q itself. A Q equal to a member root would name that member, and a verifier that holds only the root bytes cannot check for it, so the wallet does.
8. It builds the tree over `ring`, or updates a tree it kept from an earlier request by the slots that differ. Here it refuses a root that is not a point on secp256k1 (Point validation), and a root equal to −Δ, whose sum with Δ has no x-coordinate. It never asks anyone for its leaf's path in the tree, because a path names its leaf.
9. It builds the message, a deterministic CBOR map (ENV §3): `{ctx: "sdx admission v3", topic, H, rosterHash, Q, outpoint}`. `rosterHash` is SHA-256 of the root bytes, and `Q` is its 33-byte compressed encoding.
10. It proves for K's slot, with `h` as the secret and a fresh random seed (Proof randomness).
11. It returns the admission value, a deterministic CBOR map: `{t: "ct-secp256k1-v1", H, rosterHash, vin: 0, proof}`. A gated record carries it in its public field `adm`. A gated transaction that carries no record, such as one that funds later records, carries it in an output of its own, sealed the same way; the topic's rule names that output's form. `vin` names the sealing input. The proof does not bind `vin`, so a writer that seals an input other than input 0 sets it there. The proof is 2,834 bytes.

**The seal.** The proof shows nothing about Q's private key, so it is used only together with a signature by Q.
- The writer puts the admission value into the record, or into its own output. It then spends the sealing input with an ordinary `k1sign` at the same `path`, with SIGHASH_ALL and SIGHASH_FORKID.
- That signature commits to every output, including the record and its proof. So the proof cannot move to other content.
- The outpoint can be spent only once, so the record cannot be replayed in another transaction.

**What a verifier does.** A topic's admission service, or any host that receives the transaction:
1. refuses a proof type other than `ct-secp256k1-v1`, and a proof that is not exactly 2,834 bytes, before any other work;
2. takes the root bytes for `H` from its own roster state, never from the transaction, for example from roster records it has accepted, and compares their SHA-256 with the `rosterHash` the admission value names;
3. takes Q from the output that the sealing input spends;
4. MUST check the sealing input's signature, with SIGHASH_ALL and SIGHASH_FORKID, in the script interpreter;
5. if it holds the member list at `H`, refuses a Q that is itself a member root. A verifier that holds only the root bytes relies on the wallet's refusal (step 7 above);
6. only then checks the proof against its own root bytes, with the message it builds from the topic, `H`, its own `rosterHash`, Q and the outpoint that input spends.

The signature shows knowledge of x with Q = x·G. With the proof, a prover who knows no discrete-log relation between G and H knows the private key x − h of one member root. Neither shows which root.

ANC §11.3 bars an admission service from verifying record signatures "at any layer", for the reason it gives for commitment-key derivation: that needs the participant's root. The seal check needs no root. It verifies a transaction signature against the key in the spent output, as the network does for every spend, and it derives no commitment key. This draft reads §11.3 as not covering it.

**What the proof hides.** It hides which leaf is the prover's. A roster of one member names it, and empty slots hide no one. Q is public in the spent output, as every commitment key is. A roster that publishes its member roots shows the set the prover is in. A roster that publishes only its root bytes and member count shows neither the roots nor which is whose; the writer that receives the leaf list from the roster's keeper checks it against the published root bytes before it proves.

**Refusals.** The wallet refuses a `k1ring`:
- with a role other than `write` or `root`, or on `decrypt`;
- whose input lacks a member, carries any other member (a message, a key, a hash, a peer, a path into the tree or a `vin`), or has an empty `topic`, an `H` that is not an unsigned integer, or an `outpoint` that is not 36 bytes;
- whose `path` is outside the signing namespace, is not an `action` path at level 3 or 4, or names an unregistered purpose;
- whose `ring` is empty, is not a multiple of 33 bytes, or has an entry that neither starts with 02 or 03 nor is 33 zero bytes, before it prompts;
- whose `ring` has more entries than its bound, before it decodes any of them;
- that no grant covers and the user does not approve, and with role `root` when the user declines;
- whose `<h>` names no account the wallet holds, or whose `ep` names no epoch of it, checked after permissions;
- whose ring does not hold the account's root for the epoch, checked after permissions;
- whose `path` gives an offset of 0 or at least `n`, or a child key of 0 (step 3);
- whose ring holds Q itself;
- whose ring holds a root that is not a point on secp256k1, or that equals −Δ, found when it builds the tree.

### Account list and recovery

- **Recovery needs two things:** the wallet's own root, and the wallet's list of SDX accounts. The `ikm` of an account created in the wallet depends on the account ID, which SDX requires to be random and never visible on the audit layer (KEYS §1.6.2).
- **A wallet that hosts SDX accounts MUST back up the account list.** For each account it holds the account ID, its tag, its epochs and which is current, and whether each epoch was created in the wallet or imported. An imported epoch's `ikm` or seeds are backed up with it, encrypted. Without the list, recovering the wallet does not recover those accounts.
- **Runtime and chain identifiers are the runtime's.** Record key paths also name the runtime, the writer of ENV §8.5, and a chain's commitment key paths name the chain (ANC §3.1). They reach the wallet only inside request paths. The runtime keeps them in its derivation registry (KEYS §1.9.1, §1.9.2), which it can rebuild from its envelopes with the root material (KEYS §1.9.4), and the operator publishes each chain's origin identifier (ANC §4.1). A wallet MAY record the ones it sees and back them up with the list.
- **The list is small.** The wallet's own backup is enough. A file encrypted to the wallet itself also works, but BRC-39 defines only a password protector, so such a file needs the companion recipient-protector draft.
- **Devices and vendors.** BRC-250 (a draft with a proposed number) moves only the vault master to a user's new device. The account list moves with the wallet's own state or comes from its backup. Moving one SDX account to another wallet or another SDX implementation uses the companion BRC-39 recipient-protector draft, which carries the account's root material and its list entry.
- **The account ID stays random.** Deriving it from the wallet root would hand it to anyone who holds that root, which removes the barrier of KEYS §1.9.1 ("An attacker who obtains the root keying material but not the registry must guess the account identifier").
- **Epochs share the wallet root.** Every epoch's `ikm` derives from the same wallet root, so rotating to a new epoch gives no protection if the wallet root itself leaks. Recovering from that needs a new root.

### Point validation

Every `peer` and `epk` MUST be validated, on the operation's curve, before any multiplication. The checks mirror BRC-229's:
- exactly 33 bytes;
- the first byte is `02` or `03`;
- `x < p`, checked before any parser that reduces `x`. For example, a parser that reduces first reads `02 ‖ p` as `x = 0`, which is a valid P-256 point;
- the point is on the curve: `y² = x³ − 3x + b` on P-256, `y² = x³ + 7` on secp256k1;
- the point is finite.

Skipping this exposes `decrypt`, `peer` and `k1peer` to invalid-curve attacks, which leak the private scalar. For `decrypt`, the wallet converts `epk` from its JWK form to 33 compressed bytes, applies these checks, and also checks that the JWK's `y` is the point's own `y`. `k1ring` checks every root of `ring` the same way on secp256k1, although no secret multiplies them.

### Permissions

A wallet dispatches `p sdx` requests to the module ahead of its ordinary permission checks (BRC-98), so the module is solely responsible for authorizing them (BRC-116 §P-Modules, BRC-206 §Permissions). It authorizes through the wallet's trusted UI, and derives no key before a request is authorized.

**Authorization comes before what the wallet holds.** The module checks a request in three stages:
1. Checks that read only the request: the carrier method, the protocol name, `privileged` and `counterparty`, the CBOR input and the points in it, the role, `path` against the profile, the shape and bound of a `k1ring` ring, `ep` with role `actor` or `session`, the session that a `session` request names, and for `open` the tag of `acct`.
2. Grants, or the user's approval through the trusted UI.
3. Checks that read what the wallet holds: the account and epoch the request selects, `open`'s tag collision and epoch order, whether a `k1ring` ring holds the account's root, and then the operation itself.

An unauthorized request is therefore refused in the same way whether or not the wallet holds the account, the epoch, or a root in the ring, and the wallet derives no key and draws no session root for it. `open` reads whether it would create only to decide whether a grant may cover it. Without a grant, both cases prompt alike.

These rules follow BRC-229 and BRC-206, and are narrower in two ways.
- **Grant scope.** A grant is scoped to the originator, the operation, the logical protocol ID `<role> <h>`, and the path prefixes it covers. BRC-229 and BRC-206 scope a grant to the logical protocol ID alone. Here the operations reach different capabilities over the same keys: ES256 signatures, transaction signatures, decryption and admission proofs. So a grant for one never covers another.
- **Account isolation.** The logical protocol ID names the account, so a grant for one account never covers another.
- **Grant independence.** A grant for an ordinary protocol `[2, "<role> <h>"]` MUST NOT satisfy a module request `[2, "p sdx <operation> <role> <h>"]`, or the reverse. Each operation is granted separately, so a grant for `sign` does not cover `k1sign`, and a grant for `k1sign` does not cover `k1ring`.
- **No prompt allowed.** `seekPermission: false` fails without prompting.
- **What the trusted UI shows:**
  - for `open`: the account tag and the epoch, and whether the request creates the account or a new epoch;
  - for `sign`: the operation, the role, the account tag, `keyID`, `path`, and the message length and its SHA-256 digest, which is the hash ES256 signs;
  - for `k1sign`: the operation, the role, the account tag, `keyID`, `path` and `hash`;
  - for `k1ring`: the operation, the role, the account tag, `keyID`, `path`, the topic, `H`, the number of slots in the ring, and the outpoint as `<txid>.<vout>`, with the txid in its usual display order;
  - for `decrypt`: that the application is decrypting data addressed to the account's P-256 key;
  - for any request whose `peer` is the curve's generator G: that anyone who knows the root's public key can link the derived key to it (CBOR inputs).
- **`open` prompts whenever it creates.** Creating an account or a new epoch never runs under a standing grant. Returning the root public keys of an epoch the wallet already holds MAY.
- **Root actions.** Applications SHOULD use role `root` for root-level actions, such as SDX `_grantDelegation`, `_revokeDelegation` and `_rotation`, and role `write` for ordinary writes. Wallets SHOULD prompt for each `sign`, `k1sign` and `k1ring` with role `root` rather than honour a standing grant for it.

#### Path scoping

- Keys depend only on the root and `path`, so the operation and role alone do not isolate keys within an account.
- Each grant for `[2, "p sdx <op> <role> <h>"]` therefore records the derivation-identifier prefixes it covers. The wallet's grant UI chooses them and shows them, and the module rejects a `path` outside them.
- A prefix ends at a boundary of the derivation identifier. It is `<level>-`, `<level>-<namespace>-`, or a longer prefix that ends with `/` inside the key path. So a grant for one account ID cannot cover a longer ID that begins with it. The wallet refuses any other prefix when it records the grant.
- A `key` or `k1key` request without `path` returns only a root public key. Any grant for the same operation and logical protocol ID allows it, because there is no path to scope. A `key` or `k1key` request with `peer` but no `path` is rejected.
- The protocol's security level is 2, and so is every `path`'s. The module rejects any other level. The BRC-100 `counterparty` is `self` or absent.
- `privileged: true` is rejected, because no account has a privileged root.

### Containment

- The module is trusted wallet code. It MUST NOT return `ikm`, `d`, either seed, a child private key, a derivation offset, an ECDH secret, a content-encryption key or privileged material.
- It returns only public points, signatures, admission proofs and the plaintexts of JWE entries addressed to the account.
- `decrypt` returns the plaintext and keeps the content-encryption key inside the JOSE implementation.
- `k1sign` signs only the 32 bytes it is given. Like BRC-100 `createSignature` with a hash to sign directly, it trusts the application to have computed the hash of the transaction it means; the prompt shows the hash, the path and the account.
- `k1ring` returns only the admission value: the proof, and `H`, `rosterHash` and `vin`, which are public. The caller supplies the topic, `H`, the ring and the outpoint, and the input takes no message, key, hash or tree path. The wallet builds the tree and the message from those inputs and from the Q it derived itself. So the root never proves over a message a caller wrote, and never for a key other than its own child at a path that a grant or the user's approval covers. The proof shows neither `h` nor which root is the wallet's.

### Custody

SDX does not define custody. Its one rule on it is in KEYS §2.14.2: "Actors hold their keys in their own wallets; a runtime integrates with wallets and MUST NOT custody actor keys." The rule is about actor keys. An actor is a party "distinct from the runtime's own identity" (KEYS §2.2) that acts under a delegation the runtime's root grants (KEYS §2.1). The runtime's own root keying material is a separate matter. KEYS §1.4.1 and §1.4.4 let a runtime keep it in a hardware security module, an enclave or a cloud key service that derives internally, which the runtime's process asks for operations by curve. BASE §5 leaves custody topology out of scope.

For this draft, a process custodies a key when either of these holds:
1. the key's private material, or anything Containment says the module MUST NOT return, is in the process's memory or storage; or
2. the process can obtain signatures, ECDH results or decryptions under the key without a check that it cannot change or skip.

- A process that calls a wallet through this module passes the first test by Containment. It gets back only public points, signatures, admission proofs and plaintexts.
- It passes the second only as far as the wallet's grants allow. A standing grant for `k1sign` over a path prefix lets the process sign any 32-byte hash with any key under that prefix, including a hash that spends an output one of those keys locks. Within that prefix it custodies the keys in effect. A standing grant for `decrypt` likewise lets it read every entry addressed to the account under the prefix.
- A wallet limits this with the grant's prefixes (Path scoping), and MAY limit it further: for example, by checking what a hash commits to before it signs, by bounding the signatures or the value a grant covers, or by prompting. This draft defines no such check.
- Where the process and the wallet run does not decide it. A wallet on the same host passes both tests if the process cannot read the wallet's storage or change its grants. A key library linked into the process fails the first.
- SDX forbids custody of actor keys only. A runtime process MAY hold standing grants over its own account's keys, because they are the runtime's own key tree. The tests matter where a runtime process holds grants in an actor's wallet. There, by this draft's reading, a standing `sign` or `decrypt` grant under role `actor` is the custody KEYS §2.14.2 forbids.
- A deployment that states that its runtime does not custody actor keys SHOULD say which grants each runtime process holds in actors' wallets, so that a reader can apply the second test (open item 25).

### Errors

The module checks in the order of Permissions: first the request, then authorization, then what the wallet holds, then the operation. A wallet MUST fail a `p sdx` request, before it prompts and without deriving a key or drawing a session root, when:
- the method is not `encrypt` or `decrypt`, or the operation is not one that method carries;
- the protocol name is malformed, its security level is not 2, or its operation or role is unknown;
- `privileged` is true, or `counterparty` is not `self`;
- the input is not deterministic CBOR, lacks a required member, carries an unknown member or a member of the wrong type, or carries a point that fails validation, including a JWE's `epk` (Point validation);
- the operation does not allow the role;
- `path` breaks a key-path rule, is in a namespace the operation may not use, or names an unregistered purpose, or `peer` comes without `path`;
- a `k1ring` ring is malformed or over its bound;
- a request with role `actor` or `session` carries `ep`, or a `session` request names no session;
- `open`'s `<h>` is not the tag of `acct`.

It MUST then fail, without deriving a key or drawing a session root, when the request needs a prompt, because no grant covers it or Permissions requires one, and either `seekPermission` is false or the user does not approve.

Only after that does it fail because of what it holds, when:
- `<h>` names no account it holds, or `ep` names no epoch of that account;
- `open` would create an epoch other than the next one, or `acct`'s tag equals the tag of a different account it holds;
- it cannot derive the account or actor root it needs;
- a `k1ring` ring does not hold the account's root for the epoch.

And last because of the operation: a seed out of range (Canonical derivation, step 2), an offset or child key out of range (step 3), a JWE that does not decrypt, or a `k1ring` ring that holds Q or holds a root that is not a point on secp256k1 or that equals −Δ (Admission proofs).

A wallet that refuses a request under a rate bound (Resource limits) does so before it derives anything, and reports it as distinct from a denial and from invalid input.

Errors SHOULD identify the failed check, the invalid member or the denied capability, without revealing key material. Before a request is authorized, they MUST NOT reveal whether the wallet holds the account, the epoch, or a root in the ring. This draft defines no error codes; the labels in the conformance vectors are informative.

### Conformance vectors

Two draft suites go with this draft, and will be published with it:
- **VC-P256** covers `open`, account selection, the P-256 operations, permissions and request-level rejections: 177 cases, with 189 executable requests not counting variants.
- **VC-SDX-K1** covers `k1key`, `k1peer` and `k1sign`: 72 cases, with 91 executable requests.

Each suite has two independent checkers, one in JavaScript and one in Python, which import no code from the generator. Each checker's own tests alter cases and confirm that the checker catches every alteration. A reference module replays every executable case. The suites model prompts as open item 12 describes. They include cases in which a request without a grant names an account or an epoch the wallet does not hold, and is refused as one for a held account is. `k1ring` has no conformance vectors yet. Its proof type has seeded test vectors in its reference implementation (open item 20).

## Security

- **Constant-time arithmetic.** Every operation that multiplies by a secret scalar, on either curve, MUST use constant-time arithmetic.
  - A double-and-add loop that branches on each scalar bit, and runs once per bit of the scalar, leaks timing.
  - In signing it leaks the bit length of the nonce. That class of leak has recovered real private keys from smart cards and TPMs (the Minerva and TPM-Fail attacks).
  - Some general-purpose libraries implement P-256 with plain big-integer double-and-add. They are not suitable for the module.
  - The rule covers the admission prover, whose secret is `h`. The reference prover does not meet it yet (open item 21).
- **Nonces.** A wallet that holds a seed whole uses RFC 6979 deterministic nonces (Canonical derivation, step 4) and MUST NOT use a random nonce. A threshold wallet uses its protocol's joint nonce generation, which no single holder controls. No wallet accepts a nonce from the caller: the module has no nonce input.
- **Proof randomness.** The admission prover draws a 32-byte seed from the wallet's own random source, fresh for each proof, and mixes it with `h` and the statement. The module has no input for it. A repeated value would leak `h`, which links Q to its root. Proofs are therefore not deterministic, and are checked by verification.
- **Invalid-curve attacks.** Every `peer` and `epk` is validated on the operation's curve before use (Point validation).
- **Separate key universes.** A key derived for encryption never signs, a key derived for signing never decrypts, and nothing is derived under the reserved rotation namespace (Namespace separation). An unregistered purpose is refused at the derivation boundary, so a mistyped purpose fails at once instead of deriving a key no other party can match (KEYS §1.6.1).
- **Resource limits.** Decryption is cheap, but SDX reads can be high-volume. Wallets SHOULD bound the rate of `decrypt`, `peer` and `k1peer` requests per originator. Batching rules are open item 4.
  - Building the tree costs time in proportion to the ring, and a proof costs the same at any size (open item 23). A wallet that keeps its tree updates it by the slots that differ from its last ring, at a few milliseconds per slot in the reference implementation's measurements, but it still reads and compares the whole ring (open item 24). A wallet refuses a ring over its bound before it decodes any point, and a malformed ring before it prompts. Wallets SHOULD bound the rate of `k1ring` requests per originator.
- **Prompt fatigue.** Path-prefix grants keep prompts to what a user can judge. No standing grant covers creating an account, or root-level signatures and admission proofs (Permissions).
- **Containment.** The module returns only what Containment lists, so a compromised application learns no secret key material.

## Where this sits

- **Threshold (MPC) wallets host it the same way.**
  - Both seeds are threshold keys, derived from the wallet's own threshold key by a joint computation (Canonical derivation, step 1). No holder ever has the wallet root, `ikm` or either seed.
  - `sign` is threshold ECDSA on P-256 and `k1sign` threshold ECDSA on secp256k1. `peer`, `k1peer`, `key` and `k1key` use threshold ECDH, so every call needs the threshold.
  - `decrypt` needs only threshold ECDH too. Custody supplies the ECDH, and the JOSE implementation does the rest: the header processing, the Concat KDF, the key unwrap and the content decryption (open item 19).
  - `k1ring` needs no threshold protocol. Its secret is the offset `h`, which the holders compute by threshold ECDH as for any derivation, and the holder that adds `h` to its share runs the prover. The seal that uses the proof is a threshold `k1sign`.
  - Applications see the same module and the same results as with any other wallet. The one difference is that threshold signatures are not deterministic (step 4).
- **Hardware.**
  - A non-exportable enclave or passkey key cannot serve the derived tree.
  - It can back an actor's persistent P-256 key, which grants pin raw (KEYS §2.14.1), through a separate adapter, if it signs a digest it is given, as a PIV smart card does. A passkey cannot: WebAuthn signs its authenticator data and a hash of client data, never the ES256 signing input. ENV §8.7's raw recipient keys are one-time keys for a single record, not standing keys.
- **Reference implementation.** A JavaScript module on the Wallet Toolbox permission-module semantic handler (`handleRequest`, ts-stack#488), like `@bsv/ecpm-permission-module`. Binary provides it with this draft, together with tests that run it through a Wallet Toolbox permissions manager, check it against the vectors and against independent implementations of each curve, and spend an SDX anchor with a signature it produced. Its admission proofs come from a Rust crate over a vendored copy of an open-source Curve Trees implementation, built to one WebAssembly file. The module and the reference SDX library, whose admission rule checks the proofs, load that file. Native Rust, JavaScript and Go reproduce the crate's seeded test vectors byte for byte. No independent second implementation of the proof exists (open item 20).

## How SDX uses it

An SDX writer or reader running in a BRC-100 wallet uses the module as follows. Every key operation is then a standard BRC-100 call. `<h>` is the account's tag. The key paths shown use SDX's example profile, with `action` as the level-3 keyword on both curves.

| SDX need | Call |
|---|---|
| Create the account, or a new epoch for a rotation, and get its root public keys | `encrypt`, `p sdx open root <h>`, `{acct}` or `{acct, ep}` |
| Account P-256 public key | `encrypt`, `p sdx key write <h>`, `{}` (no `path`) |
| Actor's persistent P-256 key, for its DID document and grants | `encrypt`, `p sdx key actor <h>`, `{path: "2-sdx delegate-actor/0"}` |
| ES256 signature by an actor, on a delegate record | `encrypt`, `p sdx sign actor <h>`, `{path: "2-sdx delegate-actor/0", msg: signingInput}` |
| A session actor's key and signatures (KEYS §2.14.2) | `key` and `sign` with role `session` and `{path: "2-sdx delegate-account/<accountId>/runtime/<runtimeId>/session/<sessionId>"}` |
| `kid` for a P-256 recipient | `encrypt`, `p sdx peer write <h>`, `{path: "2-sdx encrypt-account/<accountId>/runtime/<runtimeId>/action/<actionId>", peer: recipientRoot}`, with `/field/<fieldName>` appended for a per-field recipient |
| ES256 record signature | `encrypt`, `p sdx sign write <h>`, `{path: "2-sdx sign-account/<accountId>/runtime/<runtimeId>/action/<actionId>", msg: signingInput}` |
| Read a P-256 entry | `decrypt`, `p sdx decrypt read <h>`, `{path, peer: writerRoot, jwe: <the reader's entry>}` |
| A chain's commitment key, for the record output (ANC §3.1) | `encrypt`, `p sdx k1key write <h>`, `{path: "2-sdx sign-account/<accountId>/runtime/<runtimeId>/action/<actionId>"}`: the record's signing path, on the other curve |
| Spend the chain's tip | `encrypt`, `p sdx k1sign write <h>`, `{path: <the previous record's commitment path>, hash: <the input's signature hash>}` |
| Rotate: sign with the outgoing epoch, and spend its tip | `sign` and `k1sign` with `ep` set to the outgoing epoch, after `open` creates the new one (KEYS §1.10.2) |
| Lock a handoff output to a recipient (KEYS §1.7) | `encrypt`, `p sdx k1peer write <h>`, `{path: "2-sdx handoff-…/action/<actionId>/handoff/<refIdHex>", peer: recipientSecp256k1Root}` |
| Spend a handoff output addressed to this account | `encrypt`, `p sdx k1sign write <h>`, `{path, peer: senderSecp256k1Root, hash}` |
| A top-up output lock, and spending it | `k1key` and `k1sign` with `{path: "2-sdx sign-…/action/<actionId>/topup/<n>"}` |
| Admission to a topic whose business rule requires a roster proof (ANC §11.1, Admission proofs) | `encrypt`, `p sdx k1ring write <h>`, `{path, H, topic, ring, outpoint}`, where `path` is the sealing input's key: the previous record's commitment path, or a top-up path for a chain's first record, and `ring` is the roster's leaf list at `H`. The result goes into the record's `adm` field, or into an output of its own for a transaction that carries no record. Then `k1sign` with the same `path` spends that input, with SIGHASH_ALL and SIGHASH_FORKID |
| Sign a request to a roster's keeper, with a key anyone can link to the account's secp256k1 root | `encrypt`, `p sdx k1sign write <h>`, `{path: "2-sdx sign-account/<accountId>", peer: G, hash}`, where G is the secp256k1 generator (CBOR inputs) |
| Sign a discovery link or pointer, with a key anyone can link to the account's P-256 root | `encrypt`, `p sdx sign write <h>`, `{path: "2-sdx sign-account/discovery", peer: G, msg}`, where G is the P-256 generator |
| Writing to a P-256 recipient | No module call: `ECDH-ES` uses a throwaway sender key, so a library does it |

Fees and change belong to the funding layer (ANC §3.4). The wallet's ordinary `createAction` and `signAction` pay them; the application builds the record transaction with the tip as an input, and supplies the tip's unlocking script from `k1sign`.

## Open items

1. **Covered by the conformance vectors, pending SDX.** VC-P256 pins step 3 on P-256 and VC-SDX-K1 on secp256k1. Once SDX publishes its own `dual-curve` suite (BASE §6 item 3), reproduce it from the same `ikm` to confirm that KEYS §1.8's child derivation matches on both curves.
2. **Done.** VC-P256 holds deterministic vectors in the style of BRC-229 and BRC-206, a real seed-rejection case, a real scalar-rejection case, and request-level rejections.
3. **Settled: `sign` takes `msg`.** This matches KEYS §1.8.3: callers pass the raw payload bytes, not a digest. `k1sign` takes `hash`, because audit-layer transaction signatures are over a signature hash the caller computes.
4. Batching rules for high-volume `decrypt`.
5. Route: a pull request to `bsv-blockchain/BRCs`, as BRC-206 went in (#347). Offer the draft to mintBlue and the ts-stack maintainers as co-authors.
6. **Withdrawn (2026-11-15).** It asked whether a P-256 key path may serve as a BRC-72 key ID, for `link`. The module no longer has `link`.
7. **Proposed: the actor root's key ID.** The draft fixes `actor` as the key ID for actor roots (step 1), so that a restored actor wallet keeps its pinned keys. VC-P256 pins the formula in one case; its other actor cases start from a fixed root.
8. **Threshold wallets: the joint derivation has no reference yet.** The joint computation of step 1 is specified by its result only. A reference implementation, and a test that runs it on VC-P256's wallet-root inputs and compares public keys, are planned. The operations that follow it are shown with a key held as two additive shares (open item 19).
9. **Not offered: secp256k1 symmetric field keys.** KEYS §1.7 gives the encryption namespace a secp256k1 role ("symmetric field-encryption keys"). ENV §8.6 and §9 wrap every field key to P-256 recipients, so no v0.1 record uses a secp256k1 field key. The module offers no operation for one. One can follow the shape of the other operations if a use appears.
10. **Withdrawn (2026-11-15).** It described a secp256k1 `link`. The module has no linkage reveals: SDX v0.1 leaves third-party verification out of scope (ENV §8.5).
11. **Listing accounts.** Applications learn account IDs from their own records. Whether a wallet should also let an application list the accounts it may use is open.
12. **Prompts in the vectors.** The executable vectors model a user who approves only the prompts that create an account or an epoch; every other request runs under a standing grant, and a request no grant covers is refused. The rule that root-role signatures prompt on every use is covered by behavioural rows only. Executable cases for it, with the request refused when the prompt is declined, are to be added.
13. **`ReadRef` and `ResponseRef` have no defined shape.** ENV §6.1 types the header's `refs` as `[ <ReadRef>* ]` and `responseTo` as `[ <ResponseRef>* ]`, and SDX v0.1 defines neither type. The module signs the bytes it is given, so it is unaffected. Records that point at other parties' records through `refs` or `responseTo` may need a new encoding once SDX defines the two types.
14. **Key-path length.** KEYS §1.3 allows key paths of 1 to 1,033 bytes, and the module rejects any other length. `path` travels inside the CBOR input, so BRC-43's 800-byte key-ID limit does not apply. SDX's worst-case derivation identifier is about 450 characters (KEYS §1.8.1).
15. **Two names for the record segment.** KEYS §1.6, §1.8.1 and §1.8.4 write a record's key path as `account/<accountId>/runtime/<runtimeId>/action/<actionId>`, and ANC §3.1 uses it for commitment keys. ENV §8.5–§8.6 write it as `account/<account-id>/<writer-scope>/<writer-id>/record/<record-id>`, make its segment literals profile parameters, and give no example `<writer-scope>`. A deployment profile fixes the words once, for both curves (KEYS §1.6.1: "spells it that way everywhere"), and the module validates paths with them. The conformance vectors use KEYS's words, `runtime` and `action`, on both curves, so a record's P-256 signing key and its secp256k1 commitment key share one key path. KEYS §1.6.2 gives no text form for `sessionId` inside a path; the vectors use step 1's form.
16. **`dref` on root records.** ENV §6.1 lists `dref` as a header member of "length 0 or 1 in this version", without the optional marker that `refs` and `responseTo` carry. KEYS §2.7 describes `hdr.dref` as absent when `pks` is `"root"`, and KEYS §2.7.1 dead-letters a root-scope record "if hdr.dref is present". Neither text says whether an empty list counts as present. The module signs the header bytes it is given, so it is unaffected. A writer that signs root records with it chooses between omitting `dref` and writing `dref: []`, and a reader that counts an empty list as present dead-letters a root record that carries one.
17. **Several installs.** The rule that only the holding install writes (Roots and selection) is a check for the host wallet. The reference module serves one install and does not model holding.
18. **Withdrawn (2026-11-15).** It recorded that `decrypt` superseded `unwrap`. `unwrap` is removed, and VC-P256 carries `decrypt` cases.
19. **Settled: threshold wallets and `decrypt`.** Custody supplies only the ECDH, or for `sign` and `k1sign` only the ECDSA, and the JOSE implementation does the rest. The reference implementation gives a JOSE implementation an external key whose one operation is that curve operation, so no private key is imported anywhere. It uses a fork of the `jose` library that adds such keys, and its tests decrypt a JWE and sign ES256 with a key held as two additive shares. Upstreaming the fork is not proposed.
20. **The admission proof needs a specification outside the code.** The reference implementation's README writes down its relation, its parameters, the tree, and every byte format. Its seeded test vectors are reproduced by native Rust, JavaScript and Go. The transcript's labels and order, and how the Bulletproofs generators and Δ are derived, are still defined only by the code and the vendored library. An independent implementation needs them written out. Conformance vectors for `k1ring` itself, checked by verification because proofs are randomised, follow from that.
21. **The reference prover is not constant-time.** Security requires constant-time arithmetic for every multiplication by a secret scalar. The reference prover's scalar multiplications and multi-exponentiations are variable-time and run on secrets: `h`, the Schnorr nonces, the re-randomisers and the proof's witnesses. Its slot search and path lookup also take time that depends on the slot, which is what the proof hides. It does not meet the MUST. Until it does, it should run only where no co-located observer can time the wallet.
22. **The composition needs a cryptographic review.** The argument that the proof and the sealing input's signature together show knowledge of a root key (Admission proofs) needs an independent review. So do the reference crate and the Curve Trees code it builds on. That code describes itself as a research implementation, and nothing on the secp256k1/secq256k1 path is known to have been audited. One property needs particular attention. The tree gadget selects a child by its x-coordinate, so it also admits −K − 2Δ + r·H as a re-randomised leaf, and the review should confirm that the Schnorr proof and the seal exclude it.
23. **Settled: the cost no longer grows with the roster.** Proving and verifying cost the same at any roster size. The reference implementation's README gives its measurements, in WebAssembly on Node 24 on one core of an Apple M3, from 2¹⁰ to 2²⁰ slots: about 1.7–2.1 s to prove and 81–82 ms to verify. Building the tree grows with the roster, to about 43 s at 2²⁰ slots, and a wallet or host builds it once. After that, setting one slot took 3–5 ms, and a block of 100 changes 28–168 ms.
24. **The ring travels in full.** `ring` is 33 bytes per slot, so a roster of 10⁶ members sends 33 MB on every `k1ring` request. BRC-100 carries it as a JSON array of numbers. A wallet that keeps its tree still receives and compares the whole ring. Passing the ring by reference, for example by its root and a source the wallet trusts for the leaves, is open.
25. **SDX does not define custody.** KEYS §2.14.2 forbids a runtime to custody actor keys and defines neither term. The Custody section gives this draft's reading. Whether SDX means the same is open. So is whether a runtime process that holds standing `sign` or `decrypt` grants in an actor's wallet conforms, or whether the actor's own client must produce each signed and encrypted payload.
26. **Detecting the module.** A caller learns whether a wallet supports `p sdx` only by sending it a `p sdx` request.
    - A well-formed request may prompt, and `open` may create an account or an epoch. BRC-205 §5 says a discovery readiness probe MUST NOT prompt for new permissions or establish an account.
    - A request with `seekPermission: false`, or one that fails the checks that read only the request (Errors), does neither. A wallet without the module refuses it too (BRC-98), and this draft defines no error codes that tell the two refusals apart.
    - The reference module declares nothing a caller can read before a request.
    - A later revision could define a probe that answers only whether the module is installed, and perhaps which profile it serves. It would say nothing about accounts, epochs or roots, as Errors requires before a request is authorized. Any such answer also helps fingerprint a wallet. BRC-205 §6 requires a scheme advertisement to state its disclosure policy.
    - BRC-205 §6 lets a BRC define a `getVersion` attribute that advertises a BRC-98 scheme, under a key `brc<number>-<name>` with its own number. BRC-205 defines no such attribute, and an advertisement is a hint: its absence does not prove that the wallet lacks the scheme. BRC-212 asks a BRC with a yes-or-no advertisement to claim a flag in its registry rather than a new key. Wallet Toolbox's permissions manager appends to `getVersion` the attributes each permission module declares (`@bsv/wallet-toolbox-client` 2.15.1).
    - This draft has no BRC number yet, so it can claim no key or flag. It does not choose how a probe would be carried.

## References

- [BRC-2: Data Encryption and Decryption](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0002.md)
- [BRC-39: User Wallet Data Format Encryption Extension](https://github.com/bsv-blockchain/BRCs/blob/master/outpoints/0039.md)
- [BRC-42: BSV Key Derivation Scheme (BKDS)](https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0042.md)
- [BRC-43: Security Levels, Protocol IDs, Key IDs and Counterparties](https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0043.md)
- [BRC-44: Admin-reserved and Prohibited Key Derivation Protocols](https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0044.md)
- [BRC-72: Protecting BRC-69 Key Linkage Information in Transit](https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0072.md)
- [BRC-98: P Protocols: Allowing Future Wallet Protocol Permission Schemes](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0098.md)
- [BRC-100: Unified, Vendor-Neutral, Unchanging, and Open BSV Blockchain Standard Wallet-to-Application Interface](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0100.md)
- [BRC-116: Wallet Permissions and Counterparty Trust](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0116.md)
- [BRC-157: Entropy-Rooted Backup and Recovery with Mnemonics and Backup Shares](https://github.com/bsv-blockchain/BRCs/blob/master/key-derivation/0157.md)
- [BRC-205: Extensible Wallet Version Strings and Account Labels](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0205.md)
- [BRC-206: Wallet-Native Rabin Signatures as a BRC-98 Module](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0206.md)
- [BRC-208: Vault Sub-Accounts](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0208.md)
- [BRC-212: Compact Wallet Feature Flags in `getVersion`](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0212.md)
- [BRC-229: Wallet-Native Elliptic Curve Point Multiplication as a BRC-98 Module](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0229.md)
- [BRC-249: Vault Account Holding Across Devices](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0249.md) (draft, proposed number)
- [BRC-250: Device Login and Recovery](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0250.md) (draft, proposed number)
- SDX Protocol specification v0.1 (2026-07-17, revised 2026-09-01), cited by part and clause:
  - BASE: [Base protocol specification v0.1](https://sdxprotocol.org/protocols/data-sharing/v0.1/)
  - KEYS: [Keys, identity and delegation](https://sdxprotocol.org/protocols/data-sharing/v0.1/keys/)
  - ENV: [The record envelope and field placement](https://sdxprotocol.org/protocols/data-sharing/v0.1/envelope/)
  - ANC: [Anchoring, addressing and retrieval](https://sdxprotocol.org/protocols/data-sharing/v0.1/anchoring/)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)](https://www.rfc-editor.org/rfc/rfc6979)
- [RFC 7516: JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516)
- [RFC 7518: JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518): ES256, `ECDH-ES+A256KW` and `A256GCM`
- M. Campanelli, M. Hall-Andersen and S. H. Kamp, "Curve Trees: Practical and Transparent Zero-Knowledge Accumulators", USENIX Security 2023

Related: drafts README · [BRC-39 recipient protector draft](brc-draft-brc39-recipient-protector.md).
