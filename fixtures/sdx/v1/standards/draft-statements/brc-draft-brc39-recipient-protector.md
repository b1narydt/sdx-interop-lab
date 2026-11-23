<!-- tpnil:draft-statement-header -->
**Draft statement.** Contributed by Binary Distributed Technologies Inc., dated 2026-11-18. It has not been adopted by the SDX working group or by any standards body, and its text is not TPNIL's. TPNIL retains it unchanged as attributed contributed material under Apache-2.0 ([CONTRIBUTING](../../../../../CONTRIBUTING.md)). Format changes only: the source's YAML front matter was removed, and links to package documents not reproduced in this directory are shown as plain text.
<!-- tpnil:draft-statement-text-follows -->
# BRC draft: a recipient protector for BRC-39 wallet data files

**Status:**
- Draft from Binary, 2026-11-10, revised 2026-11-12 (drafts README). Not yet submitted.
- It would go through the BRC process as an extension of BRC-39. Byte values marked *to be assigned* need the BRC-39 maintainers.
- Draft vectors (VC-B39R) exist, with independent checkers. They are not yet published.

## Abstract

BRC-39 defines an encrypted wallet data file (`WDAT`) whose only protector is a password. This draft adds two things:
- **Protector type `0x02`, recipient, under Format Version `0x02`.** The file's content key is random and is wrapped to one recipient's identity key with BRC-78.
- **One new inner format:** an SDX account package (§2), so that an SDX account can move between implementations.

Together they let a wallet or SDX implementation:
- hand an account to another implementation;
- back up key material to a store that cannot read it;

with no password to share. BRC-39 §10.2 already anticipates this: "future protector types MAY define such a mode".

## Motivation

- **BRC-40 does not encrypt.** BRC-40 moves wallet storage between providers, and it explicitly leaves out the encryption of exported wallet data. Outputs and proofs are public, so that is acceptable for them. It is not acceptable for root or seed material.
- **BRC-39 encrypts, but only with a password.** A password has to be shared, which is the wrong tool for a device-to-device or provider-to-provider handover, and for a backup kept by a storage host.
- **BRC-38 and BRC-39 carry wallet data, never keys.** BRC-38 is a plaintext export of one user's Wallet Toolbox storage, and BRC-39 wraps it under a password; as revised on 2026-10-15 it still defines only the password protector. Wallet Toolbox implements both (`exportBRC38`, `importBRC38`, `exportBRC39`, `importBRC39`), and states that BRC-39 exports "contain wallet data, not root keys". Keys move by other means: BRC-208 derives every account from one vault master, and BRC-250 sends that master to the user's new device. None of them moves one account's root material to another wallet or another vendor.
- **SDX needs this envelope in two places.** SDX v0.1 says that "every record and proof is portable and exportable", but defines no package for moving an account. A package that carries root or seed material must be encrypted to its recipient. So must a backup of an imported root kept by a storage host, so that the host cannot read it.

## Specification

### 1. Protector type `0x02`: recipient

**Format Version.** A recipient-protected file uses Format Version `0x02`. BRC-39 §14.3 lists protector type 2 as a file an importer must refuse under Format Version `0x01`, so a version-1 importer refuses these files by their version, before it reads any new field.

**Header.** The file keeps BRC-39's field order up to the reserved bytes. Offsets count from 0, the first byte of the file. `L` is the Wrapped Key Length.

| Field | Offset | Value |
|---|---|---|
| Magic | 0–3 | `WDAT` |
| Format Version | 4 | `0x02` |
| Protector Type | 5 | `0x02` |
| Inner Format | 6 | `0x26` (BRC-38 wallet data) or the SDX account package code (§2) |
| KDF Type | 7 | `0x00` (none) |
| Flags | 8 | `0x00` |
| Salt Length | 9 | `0x00` |
| Nonce Length | 10 | `0x20` |
| Argon2id fields | 11–20 | All zero, including Hash Length |
| Reserved | 21–32 | 12 zero bytes |
| Wrapped Key Length `L` | 33–34 | 2 bytes, big-endian, from 1 to 1024 |
| Wrapped Key | 35 | `L` bytes: a BRC-78 message whose plaintext is the 32-byte content key `K` |
| Salt | absent | Length 0 |
| Nonce | 35+L | 32 random bytes |
| CiphertextAndTag | 67+L | AES-256-GCM of the inner payload under `K`, followed by a 16-byte tag |

**Sizes.** A 32-byte `K` wraps to a 182-byte BRC-78 message, so `L` is 182. The header, wrapped key and nonce then take 249 bytes, and the ciphertext and its 16-byte tag follow.

**Export.**
1. Choose a random 32-byte `K` and a random 32-byte nonce.
2. Wrap `K` to the recipient's identity key with BRC-78, from the sender's key:
   - **Sender key.** For a handover, the sender is the exporting party's identity key, which authenticates the source. For a backup to oneself, the sender is the wallet's own identity key. When the sender's identity must not appear, it is a one-time key.
   - **Additional authenticated data.** Encrypt the payload with AES-256-GCM under `K`. The additional authenticated data is bytes 0 up to 35+L: every field from Magic through Wrapped Key. This differs from protector `0x01` and binds every header field to the ciphertext.

**Import.**
1. Validate the header (§3) before unwrapping.
2. Check that the BRC-78 recipient key equals the importer's identity key, and refuse otherwise.
3. Unwrap `K`.
4. Decrypt with the header as additional authenticated data.
5. Parse the inner payload by its Inner Format.

### 2. Inner format: SDX account package

- **Code.** *To be assigned.* BRC-39 uses the BRC number for BRC-38. This format has no BRC number of its own, so it needs an assigned code, written here as `TBA`.
- **Payload.** A deterministic CBOR map (SDX ENV §3) holding:
  - the account ID and its deployment profile (KEYS §1.3.1);
  - the epoch table: each epoch's number, its secp256k1 and P-256 identity public keys, and its state, `active` or `archived`;
  - the root material for each epoch: the 64-byte root keying material (KEYS §1.4.1), or the two per-curve seeds where the sender holds them as managed keys (KEYS §1.4.4);
  - the derivation registry (KEYS §1.9);
  - chain state: for each chain, its ID, topic and tip outpoint, with BEEF;
  - the outputs the account controls, each with its namespace and key path, with BEEF;
  - active grants, which the recipient can also rebuild from the chain;
  - optionally, with the holder's consent, identity-link rows (KEYS §2.12.3), which are personal data;
  - the time of export.
- **Backups.** A backup is the same package carrying only the account ID, its profile, the epoch table and the root material.
- **Vectors.** VC-B39R does not yet cover this inner format, because its code is unassigned.

### 3. Validation

An importer MUST refuse a protector `0x02` file before unwrapping when any of these hold:
- Format Version is not `0x02`;
- KDF Type is not `0x00`;
- Salt Length is not `0`, or Nonce Length is not `32`;
- any Argon2id field is non-zero;
- Flags or any reserved byte is non-zero;
- Wrapped Key Length is `0` or greater than `1024`;
- the Inner Format is unknown;
- the BRC-78 recipient is not the importer's identity key.

An importer MUST also refuse the file when:
- the unwrapped `K` is not exactly 32 bytes;
- the Wrapped Key Length does not match the length of the BRC-78 message. Unwrapping then fails.

A file whose GCM tag fails MUST be refused as a whole, and no partial plaintext may be used.

## Security and privacy

- **Visible identities.** BRC-78 carries the sender and recipient identity keys in clear. Anyone holding the file can see who sent it to whom. When that matters, use a one-time sender key, and deliver the file over an authenticated channel such as BRC-103.
- **No forward secrecy.** Anyone who later obtains the recipient's identity key can open stored files.
  - For handovers, delete the file after import.
  - For backups, this is intended: the recipient key is the user's own, and the wallet's recovery covers it.
- **Header binding.** Binding the header as additional authenticated data stops an attacker relabelling the inner format, or swapping the wrapped key, without detection.

## Open items

1. **Resolved.** The file uses Format Version `0x02` (§1), so the KDF Type `0x00` and the two new header fields belong to the new version.
2. Assign the SDX account package code.
3. **Resolved.** BRC-78 unwrapping is reachable through BRC-100: `decrypt({protocolID: [2, 'message encryption'], keyID: base64(keyID), counterparty: sender})` unwraps a BRC-78 message, so wallets need no raw key access (vector VC-B39R-003).
4. **Resolved.** Draft vectors exist (VC-B39R): a handover file, a backup file, and the refusal cases in §3.
5. **Reference implementation.** Add protector `0x02` and the SDX account package to Wallet Toolbox's existing `encryptBRC39` and `decryptBRC39`, so wallets that already read and write BRC-39 files gain the recipient protector with one change.
