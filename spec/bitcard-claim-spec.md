# Bitcard Claim Specification

**Version 0.4 — DRAFT (2026-07-01): the maker signature is REMOVED.**
Bitcard is an **open, permissionless standard**: cards carry no issuer key, the QR payload is just `base64url(record)`, and anyone may build a compatible card or tool (like BIP39). Why it was dropped: the signature protected funds in **no** way (the 2-of-2 scheme does that), did not stop the counterfeit-app phishing path (the QR chooses the verifier), added a signing key that would have to stay secret for 100+ years — against the "runs without us" ethos — and gated "genuineness" in a way that fights the open design. Effects: **no issuer signing key or signature ceremony anywhere (the maker half-key and its destruction ceremony, section 2a, are unchanged)**; the QR is **smaller** (v7 / 45 modules vs v9 / 53 → bigger, easier-to-scan modules); mainnet is now a pure network-config swap (`build/config.js`, flip `ACTIVE`). Anti-brand-impersonation, if ever wanted at retail, becomes a **serial-lookup registry**, not a crypto gate. The two-half key scheme, the record format (§4.1), the flows (§6), the sweep rules (§7), and recovery (§8) are unchanged. **AUTHORITATIVE ON-THE-WIRE FORMAT: §4.1 and §4.3 (QR payload = base64url of the record, with nothing appended).** There are **two record versions and both are valid forever**: **v1 is 41 bytes** (the 2026 pilot cards) and **v2 is 46 bytes**, identical to v1 except that `version = 0x02` and a 5-byte SHA-256 checksum is appended. New cards MUST be minted as v2; a conformant parser MUST accept both, MUST verify the v2 checksum, and MUST reject unknown version bytes. Read the version byte first and take the length from it; never assume a fixed length. Any wording anywhere below — including §4.4, §6, and the §0/§0a changelogs — that mentions a maker signature, an Ed25519 key, `sig(64)`, a 105-byte payload, the app "verifying" a card, or a record that is *only* 41 bytes, is superseded text kept for history. A conformant parser expects no signature.

**Security model, stated honestly.** This is an **additive two-part key**: the two halves add to one ordinary P2WPKH key (`d = (d1 + d2) mod n`). It is NOT an on-chain 2-of-2 multisig and provides none of multisig's on-chain features (independent signing, timelocks, revocation, a recovery descriptor). Its protection is **pre-claim compartmentalization**: before claim, neither half alone can spend. At claim, the full key is reconstructed. The hosted claim app reconstructs it inside a web page, so **that path trusts the app delivery** (acceptable for small gifts: verify the published hash and load only from the official address). For larger amounts, an **offline tool** (`offline.html`, CSP `connect-src 'none'`, no network code) reconstructs the key on-device and hands it to a standard wallet's Sweep. It **refuses word entry unless run from a saved local file** (`file://`), because a page served live is only as trustworthy as its delivery; the trust-minimizing path is download, verify the file hash, disconnect, open the saved file. "Recoverable forever" means: from the two word-halves, via the open method or the included tool; the recovered key is a standard WIF any wallet can sweep (a normal wallet cannot recover from either 12-word phrase alone, because each is used as a BIP32 master scalar and the two are added).

**Version 0.3 — HISTORICAL NOTE (superseded by v0.4 above; NON-NORMATIVE — do not implement from this paragraph).**
Signed-QR verification *(removed in v0.4 — no signature exists)*, CSP, the §7 multi-node sweep (with decoded destination confirmation and fee sanity bounds), and the best-effort claim-flow model were implemented in the v0.3 reference app. (Maker/recipient tooling separation and the Part-1 ceremony tooling were built then too — a public claim app with no maker key, an offline create-only maker tool, and a separate keyless QC tool that verifies each sealed card before it ships.)

This document defines exactly how a Bitcard splits, combines, encodes, authenticates, and claims a Bitcoin key. It is the open standard that lets any compatible tool recover a card's funds even if every Bitcard service disappears.

## 0a. Changes in v0.3 (second-review response) — *HISTORICAL, NON-NORMATIVE. Do not implement anything in this section. Every signature/Ed25519 item was REMOVED in v0.4; the authoritative format is §4.1 + §4.3 (v1 41-byte / v2 46-byte record, no signature).*

- *(removed in v0.4)* Maker signature was changed to Ed25519 (was BIP340), for clean separation from Bitcoin keys. **No signature exists in v0.4.**
- *(partially superseded)* Card record frozen (§4): fixed-width fields, explicit enum byte values, 4-byte big-endian serial. The record layout survives in v0.4; the signature and `app_id` parts were removed.
- **P2WPKH confirmed for the first mainnet batch**; Taproot deferred to a later version (§10). *(still current)*
- **Part-1 destruction is a defined manufacturing ceremony** (§2a): read-back the sealed words against the record's `P1` (v0.4: build the record, nothing is signed), witnessed destruction, batch audit. *(still current, minus signing)*
- **App must display its own runtime build hash** (§5.7), verifiable against the published bundle hash. *(still current)*
- **Reproducibility inputs** now include `package-lock.json` and `assemble.mjs` (§8). *(still current)*
- *(historical implementation status)* The v0.3 reference app implemented signed-QR verify *(removed in v0.4)*, CSP, build-hash display, best-effort secret hygiene, and the §7 multi-node sweep. Maker/recipient tooling separation implemented (§10). *(all still current except the signature)*

---

## 0. Changes in v0.2 (response to review) — *HISTORICAL, NON-NORMATIVE. Signature language below is v0.2-era; the signature was removed in v0.4.*

| # | Finding | Resolution in v0.2 |
|---|---|---|
| P0 | Offline mode doesn't protect Part 2 from a malicious/changed app | New **§5 App authenticity & integrity** — self-contained, reproducibly built, pinned, no external scripts/analytics/service-worker, no persistence, best-effort secret hygiene (DOM clear + key zeroize), user-verifiable hash. Offline is necessary, not sufficient; the real anti-tamper control is the pinned/audited hash, not the hygiene. |
| P0 | QR `<host>` is a phishing/counterfeit path | **§4 rewritten** — *(v0.2 answer; the signature was removed in v0.4)* the QR carried a maker-signed record and a content-addressed app URL. **v0.4 answer:** the QR carries the unsigned record (§4.3); the trust anchors are the **hash-verified app** (published SHA-256 + self-displayed build hash, §4.4) and **tamper-evident physical packaging**. |
| P1 | Balance check dangerous if maker retains Part 1 | **§2/§9** now **require the maker to destroy Part 1** after manufacture. **§6.2** derives the address offline, zeroizes secrets, then queries — or uses the non-secret funding address as a view handle. |
| P1 | "Recipient is the only party" overstated | **§9** states the collusion/breach limit explicitly **and** removes the standing risk by mandating Part 1 deletion. |
| P1 | Recovery format not frozen | **§3/§8** freeze version, network, script type, KDF, BIP39 language + normalization, rejection rules; **test vectors** are a release gate. |
| P1 | Handwritten Part 2 can burn funds | **§6.1** requires re-entering the written 12 words and confirming the **same address** before funding. |
| P2 | Scalar/point validation too loose | **§3.4** full validation rules; wraparound is normal, only zero/infinity is fatal. |
| P2 | Sweep details security-relevant | New **§7 Sweep rules** — fee caps, UTXO discovery, dust, deterministic nonces, destination confirmation, RBF, multi-node broadcast, audited libs. |

Not changed: additive aggregation itself (the reviewer did not block on it; see §3.3 and §10).

---

## 1. Purpose and principles

A Bitcard carries the keys to bitcoin at an ordinary Bitcoin address. This spec guarantees:

- **Non-custodial.** The maker never holds the full key or the funds, **and does not retain either half after manufacture** (§2).
- **Two-party protection.** Neither the maker nor the gift-giver can spend alone; only the holder of both halves can.
- **Recoverable without us.** Anyone can reconstruct the key and sweep using standard secp256k1 tooling by following this spec and its test vectors.
- **No backend, authenticated app.** All key operations happen in a verified, self-contained, offline-capable app (§5). Network calls (UTXO lookup, balance, broadcast) go only to public nodes; the app is verified by its published hash, and secret hygiene during those calls is best-effort (§5.4).

---

## 2. Roles and the two halves

- **Part 1 — maker's half.** Generated by the maker on an air-gapped machine at manufacture. Its **private** value is printed/sealed under a tamper-evident scratch on the card and then **destroyed by the maker** — no database of Part-1 private keys is kept. The maker retains only Part 1's **public** key (embedded in the QR record). In v0.4 the maker holds **no key of any kind** beyond manufacture: no signing key exists.
- **Part 2 — buyer's half.** Generated by the buyer's device during setup, never transmitted, written by hand as 12 words, then sealed.
- The **recipient** ends up holding both: Part 1 by peeling the maker's seal, Part 2 from the written words.

### 2a. Part-1 manufacturing ceremony (mandatory)
Because Part 1 is destroyed, a mismatch between the sealed words and the `P1` in the card's record would lock funds forever. Each card MUST go through:
1. Generate Part 1 on the air-gapped machine; derive `P1` from the **exact words that will be sealed**.
2. Build the card record (§4) with **that** `P1` (v0.4: the record is not signed).
3. **Read-back / scan the printed-and-sealed words** and re-derive `P1`; confirm it equals the record's `P1` **before** the seal is closed and before the maker copy is destroyed.
4. Handle printer memory and waste prints securely (no Part-1 residue leaves the room). **Never write Part-1 words to a cloud-synced or version-tracked location** (OneDrive/Dropbox/git): deleting such a file does not remove its retained history. Use an ephemeral, non-synced path and destroy it after the print artifacts are made.
5. **Witnessed destruction** of the maker's Part-1 copy; **batch audit** log (serials, records, destruction sign-off) retaining only public data.

**Tooling (implemented).** A dedicated **keyless QC tool** (`print/qc-tool.html`) performs step 3 + the audit of step 5. It imports only public operations from `core.js` — **no card creation** — so it runs on a separate station from the maker tool. The operator records operator/witness IDs, re-types the words read off the **physical** sealed card, and scans its QR; the tool re-derives `P1` and confirms it equals the `P1` in the QR's record (MATCH = recoverable; MISMATCH = do not ship). After a MATCH the operator destroys the maker copy and records a **destruction sign-off**. It maintains a **durable, exportable batch audit** (JSON): per card — serial, full record + its SHA-256, public key, PASS/FAIL, timestamp, operator, witness, destruction sign-off; the read-back words are never recorded and are cleared after **every** check (success or error). (The maker tool, `maker-tool.html`, is create-only; both tools are keyless in v0.4.)

**Batch acceptance (SOP).** A batch may ship only if, across its audit export: (1) there are **no FAIL cards**, (2) **no PASS card is awaiting destruction sign-off**, and (3) **no card has an unset operator or witness ID**. Any FAIL card is destroyed, not shipped. The exported audit carries exactly these fields, so acceptance is checkable from the record.

---

## 3. Cryptographic scheme

### 3.1 Primitives (frozen for v0.2)
- Curve: **secp256k1**; order `n`; base point `G`.
- Mnemonic: **BIP39, English wordlist, 12 words (128-bit entropy)**, Unicode **NFKD** normalization, **empty passphrase**.
- Seed: BIP39 `PBKDF2-HMAC-SHA512`, 2048 iterations (per BIP39).
- Half scalar: from the seed, take the **BIP32 master private key** `k` (HMAC-SHA512, key = `"Bitcoin seed"`, left 32 bytes); the half scalar is `k` (reject if `k == 0` or `k >= n`).
- Network and script type are explicit fields (§4), **frozen for v0.2 as: network ∈ {mainnet, testnet, signet}, script type = P2WPKH** (bech32). (Taproot is deferred — §10.)

### 3.2 The two scalars
- Part 1: `d1` from the maker's 12 words → `P1 = d1·G`.
- Part 2: `d2` from the buyer's 12 words → `P2 = d2·G`.

### 3.3 Aggregation (additive single key)
- Combined private key: `d = (d1 + d2) mod n`.
- Combined public key: `P = P1 + P2` (EC point addition) `= d·G`.
- Funding address: **P2WPKH** of compressed `P`.

### 3.4 Validation rules (mandatory)
- Reject any half scalar that is `0` or `>= n`.
- Validate `P1` is a valid **compressed point on secp256k1** and **not** the point at infinity, before use.
- After aggregation, reject if `d == 0` or `P` is the point at infinity (a deliberately crafted Part 2 could target this; at setup, re-roll Part 2; at claim, treat the card as invalid).
- Modular wraparound when `d1 + d2 >= n` is **normal and fine** — only `0`/infinity is fatal.
- Enforce the BIP39 checksum on every entered mnemonic.

---

## 4. Card authentication & QR encoding

The QR carries only the data record (§4.1, §4.3: v1 41 bytes, v2 46 bytes) — **no signature.** It may direct the user to a **hash-verified** app (§4.4); the verified app (confirmed by fetched-file SHA-256 + self-displayed build hash) together with the **tamper-evident physical card** are the trust anchors. The record itself is not authenticated by any issuer key (see §4.2); genuineness of a *branded* card is a physical/packaging + optional serial-registry concern, not a crypto gate.

### 4.1 Card record (frozen — record v1: 41 bytes, record v2: 46 bytes)
| Offset | Len | Field | Value |
|---|---|---|---|
| 0 | 1 | version | `0x01` (record v1) · `0x02` (record v2) |
| 1 | 1 | network | `0x00` mainnet · `0x01` testnet · `0x02` signet |
| 2 | 1 | scripttype | `0x01` = P2WPKH |
| 3 | 1 | kdf_id | `0x01` = BIP39(en,NFKD,empty) → PBKDF2-HMAC-SHA512 x2048 → BIP32 master priv (HMAC-SHA512, key=`"Bitcoin seed"`, left 32) |
| 4 | 33 | P1 | compressed secp256k1 public key of the maker's half |
| 37 | 4 | serial | `uint32`, big-endian |
| 41 | 5 | checksum | **record v2 only.** First 5 bytes of `SHA-256(record[0..40])`, i.e. over the preceding 41 bytes with `version = 0x02`. |

**Record v2 (2026): integrity checksum.** Record v1 has no integrity check, so roughly 47% of single-character substitutions in a hand-typed card code still decode to a structurally valid record carrying a *different* valid `P1`. In the give flow that silently addresses funds to a key nobody holds (QR scanning is immune — Reed-Solomon decoding either returns correct bytes or fails — but typed and OCR'd codes are not). Record v2 appends a 5-byte truncated SHA-256 so a corrupted code is rejected outright (odds of a random corruption passing: 2^-40). The checksum covers **every** preceding byte including the serial. A conformant parser: **MUST** verify the checksum of a v2 record and reject on mismatch; **MUST** reject unknown version bytes; and **MUST continue to accept record v1 forever** — v1 cards printed in 2026 are bearer instruments that remain valid for as long as one exists. New cards **MUST** be minted as v2. 46 bytes encodes to 62 base64url characters, which keeps the printed QR at the same version and module count as v1 (measured: QR version 5, 37 modules, at ECC-L).

**Serials are display/inventory only.** A serial is not authenticated (anyone may mint a card with any serial), so no tool may use it for authorization, recall, or any trust decision. The v2 checksum protects a serial against *accidental* corruption, not against deliberate forgery. Brand-level recall/lookup, if ever needed, requires a separate signed registry keyed by serial; until that exists, treat serials as cosmetic.

### 4.2 Card authenticity — REMOVED in v0.4
Earlier drafts (v0.2–v0.3) signed the record with an Ed25519 maker key. **v0.4 removes this entirely.** Cards carry no signature and the app verifies no issuer key. This does not affect fund security (the 2-of-2 scheme, §3, is untouched) or the QC pairing check (§2a re-derives `P1` from the sealed words directly). Brand-authenticity (distinguishing a genuine-brand card from a counterfeit sold under the name) is out of scope of the crypto; if wanted at retail it is a serial-lookup registry + physical anti-counterfeit, not a signature.

### 4.3 QR payload — data record (v0.4)
```
record(41 or 46)  ->  base64url_nopad   // v1: 41 bytes -> 55 chars; v2: 46 bytes -> 62 chars
```
The QR payload is just the base64url of the record — **no signature appended.** The app decodes the record, validates the enums (version / network / scripttype / kdf — rejecting unknown values and any network mismatch), verifies the v2 checksum (§4.1) before reading any other field, and checks that `P1` is a valid secp256k1 point, **before any key material is generated.** Nothing in the QR is secret; it does not reveal the funding address (that also needs Part 2).

### 4.4 QR delivery — domain pointer, permanence via published hash + mirrors
The QR encodes:
```
<APP_URL> + "#" + base64url_nopad( record(41) )
```
where `APP_URL` is the official app address baked into the QR. For retail usability this is a short **domain** (currently `https://bitcards.xyz/app.html`), not a content-addressed gateway URL. One scan opens the app with the card record in the URL **fragment**; the app reads `location.hash`, prepends `bitcard:`, and validates as in §4.3.

The domain is a **convenience pointer, not the trust anchor.** The exact app file has a **published SHA-256**, the app self-displays its own code fingerprint (§5.7), and the byte-identical file is mirrored on GitHub, archive.org, and Arweave (content-addressed). If the domain ever served different bytes or disappeared, the app stays verifiable and the funds stay recoverable from those copies plus the two-half words. In short: **domain for convenience, published hash + redundant copies for permanence, the words for the ultimate guarantee.** A domain failure costs convenience, never funds.

Why this is acceptable (and how it differs from the original "host phishing" path):
- **Content-addressing prevents silent content substitution.** The identifier (IPFS CID / Arweave tx) is immutable and resolves from *any* gateway, so no single domain is a chokepoint and a gateway cannot serve different bytes for the same id without it being detectable. (A gateway URL still contains a domain for transport — the claim is *not* "no domain", it is "no undetectable substitution".)
- **Final acceptance rests on verification, not on trusting the host.** Before any address is printed, the published copy is confirmed by **fetched-file SHA-256** and the app's **self-displayed build hash**; both must equal the audited values. That hash-verified app, plus **tamper-evident packaging** on the physical card, is the trust anchor — not arweave.net or any gateway.
- The fragment (`#…`) is **never sent to any server**, so no host learns which card was scanned.
- Residual: a fully counterfeit card could embed a QR to an attacker's app — unchanged from the data-only design in practice (a fake card can also print fake instructions). Mitigated by trusted distribution, tamper-evident packaging, the **published official `APP_URL` + hash**, and the app's self-displayed build hash.

*(Earlier draft used a host-free `bitcard:` payload with the app obtained out-of-band; Option A is adopted for retail usability and is pending the security reviewer's confirmation that content-addressing resolves the host concern. Implemented in `claim-app.html` + `print/_genqr.py`.)*

---

## 5. App authenticity & integrity requirements (the real protection)

Airplane mode alone does not protect Part 2 — a tampered app could store it and exfiltrate later, or show a wrong address/destination. The app MUST therefore be:

1. **Self-contained.** A single, static bundle. **No** external scripts, fonts, analytics, trackers, CDNs, or service workers.
2. **Reproducibly built and content-addressed.** Published source → reproducible build → hash → pinned to IPFS/Arweave. The app displays its own build hash; users can verify it matches the published, audited hash.
3. **No persistence of secrets.** Secrets live only in memory, zeroized after use; no `localStorage`, `IndexedDB`, cookies, or cache of secret material. Ever.
4. **Secret hygiene (best-effort in v1).** Secret inputs are cleared from the DOM immediately, before any network call, and private-key bytes are zeroized after signing. **Honest limitation:** in the single-page claim flow the reconstructed key remains in memory across the UTXO-fetch and broadcast network calls, so this is best-effort hygiene, *not* a hard "no network while secrets present" guarantee. The control against a tampered build that would abuse that window is hash-pinning + audit (items 1–2), not this hygiene. **Decided for v1: best-effort hygiene** — the recipient enters secrets once; the integrity controls (items 1–2) are what protect against a hostile build. A strict offline/online split that removes secrets from memory before any network call remains available as **optional advanced hardening** but is **not required for v1** (§10).
5. **Open-source and auditable** (v0.4: no issuer key of any kind is compiled in).
6. **Offline-capable / savable.** After first load there is no host dependency; the app runs from a saved copy.
7. **Displays its own runtime build hash.** On load the app SHA-256-hashes its own inline script and shows it, so a user can compare it to the published bundle hash. (Self-hashing, not a static label.)

Offline is *necessary but not sufficient*; (1)–(5) and (7) are what actually let a user trust the running code.

---

## 6. Flows

### 6.1 Setup & load (buyer)
1. Open the **verified official app**; scan the card; the app validates the record structure (enums + `P1` is a valid curve point) and reads `P1`, `network`, `serial`. (There is no issuer signature to verify; see §4.2.)
2. App enters secret state (no network), buyer adds entropy.
3. App generates Part 2 (12 words) → `d2` → `P2`; computes funding address `= P2WPKH(P1 + P2)`.
4. App shows the 12 words; buyer **writes them on the card**.
5. **Mandatory verification:** buyer **re-enters the written 12 words**; the app re-derives and confirms the **identical address**. Funding is blocked until this matches.
6. App displays the funding address (and may output it as a non-secret view handle, §6.2). Buyer leaves secret state, sends bitcoin, seals the words, gifts the card.

The app never needs Part 1 here. The maker is never involved.

### 6.2 Check balance (holder)
Two allowed methods, both keeping secrets away from the network:
- **View handle (preferred):** use the funding **address** captured at setup (non-secret) to query a public node.
- **From the card:** enter Part 2 **while offline**, derive the address, **zeroize Part 2**, *then* go online and query.

Either way, balance needs Part 2 (or the saved address); a random scanner sees nothing. A giver who knows Part 2 can see balance but **cannot spend** (needs sealed Part 1).

### 6.3 Claim / sweep (recipient)
1. In the verified app, enter Part 2 (written words) and reveal & enter Part 1 (peel the scratch).
2. App reconstructs `d = (d1 + d2) mod n` (with §3.4 validation), derives `P`/address, confirms balance.
3. Recipient enters their own destination address; the app shows it for **explicit confirmation**.
4. App builds, signs, and broadcasts a sweep per §7.

Both halves exist together only here, only on the recipient's device. **Secret hygiene is best-effort (§5.4):** inputs are cleared from the DOM as soon as they are read and key bytes are zeroized after signing, but the reconstructed key is in memory across the UTXO-fetch and broadcast. This window is safe because the app is open-source, audited, and hash-verified (§5): the published code only ever transmits the signed transaction, never secret material. The integrity guarantee, not memory timing, is what protects the recipient.

---

## 7. Sweep transaction rules

- **UTXO discovery:** enumerate all UTXOs at the funding address from ≥2 independent public nodes; require agreement before spending.
- **Signing:** use an **audited** secp256k1 library with **RFC 6979 deterministic nonces** (or BIP340 for taproot). Never roll custom nonce code.
- **Fees:** estimate from current mempool with an **upper cap and sanity bounds**; never spend more than a configured % of value on fee; warn on unusually high fees.
- **Dust:** if value after fee is below the dust threshold, refuse and explain.
- **Destination:** require explicit on-screen confirmation of the destination; default to sweeping the full balance (no change output) to the recipient.
- **RBF** enabled; provide CPFP guidance if stuck.
- **Broadcast** via ≥2 public nodes; verify acceptance.

---

## 8. Recovery without Bitcard (frozen format + the safety net)

With only the card and this spec, anyone can recover the funds offline:
1. Read Part 1 (12 words, under the scratch) and Part 2 (12 words, written).
2. For each: BIP39 (English, NFKD, empty passphrase) → seed → BIP32 master private key (§3.1), reject `0`/`>= n`.
3. `d = (d1 + d2) mod n` (apply §3.4 validation).
4. Derive `P`, the P2WPKH address (network per the card record), sweep with any audited secp256k1/Bitcoin library per §7.

**Release gate:** the published spec ships with a reference implementation and **frozen test vectors** (`bitcard-test-vectors.json`) so independent tools can verify byte-for-byte. No mainnet issuance before these exist and pass independent reproduction.

**Reproducibility inputs** (to rebuild a self-contained app and match its hash): `build/core.js`, `build/config.js`, the app entry (`build/app-claim.js` / `app-maker.js` / `app-qc.js`) and its template, `build/package.json`, `build/package-lock.json`, `build/assemble.mjs`, and the pinned esbuild command. The build is deterministic given these; the app self-hashes at runtime (§5.7) so a user can confirm the running code matches the published bundle hash.

---

## 9. Security properties and honest limits

- Security against **the maker**: with Part 1 **destroyed**, the maker holds neither half — best case. (If a maker copy survived, security would reduce to Part 2's 128 bits.)
- Security against **the giver**: Part 1 is sealed and not known to the giver → 128 bits, uncrackable, while the seal is intact (tamper-evident).
- **Honest limit — collusion/breach:** a party that obtains **both** halves can spend. Mandating Part 1 deletion (§2) removes the standing maker-retention path, but a compromise at manufacture-time, or a giver who copied Part 2 *and* later defeats the Part 1 seal, could still steal. Seals make this **evident, not impossible**.
- **Bearer instrument:** whoever physically holds the card and opens both seals controls the funds.
- **Trust-minimized, not "zero trust"; not "hack-proof."**

---

## 10. Status & remaining items before mainnet

**Resolved in v0.3 (historical):** script type = **P2WPKH** for the first batch (Taproot later) *(still current)*; maker signature = Ed25519 *(REMOVED in v0.4 — no signature exists)*; card record **frozen** (§4) *(the record survives; the signature part was removed)*; Part-1 destruction **ceremony defined** (§2a) *(still current, minus signing)*; **claim-flow security model = best-effort hygiene** (one-time secret entry; the anti-tamper control is hash-pinning + audit per §5, not memory timing) *(still current)* — the strict offline/online split is deferred to an optional advanced mode.

**Implemented in the reference app** *(v0.3 status; in v0.4 "signed-QR verification" became structural record validation — no signature)*: card validation + malformed-card rejection, CSP, runtime build-hash self-display, best-effort secret hygiene (immediate DOM clear + key-byte zeroize), and the **§7 multi-node sweep** — UTXO read requiring all nodes to respond and agree on full spend-critical data (txid, vout, value, confirmed status) before signing, network fee estimation with a **sat/vB sanity ceiling**, fee cap + dust refusal + RBF, **decoded destination confirmation** (the recipient confirms the address decoded from the signed tx, gated by a confirm box, before broadcast), and broadcast posted to all nodes. Validated on testnet, then proven end-to-end on mainnet (2026-07-15).

**Maker/recipient tooling separation — IMPLEMENTED.** The build is split from a shared public-only `core.js` into separate artifacts: a **public claim app** (`print/claim-app.html`) that contains **no card-creation**, and a separate **offline maker tool** (`print/maker-tool.html`) that makes no network calls and is not for distribution. *(v0.4: both tools are keyless — the maker signing key this paragraph once described no longer exists.)* Cross-verified end-to-end: a card created by the maker tool loads in the claim app; both self-tests pass.

**Part-1 ceremony tooling — IMPLEMENTED (§2a).** A dedicated **keyless** QC tool (`print/qc-tool.html`, no maker private key) verifies each sealed card (re-derive `P1` from the read-back words and confirm it equals the `P1` in the card's QR record), records a destruction sign-off after a MATCH, and keeps a durable exportable batch audit (serial, record + SHA-256, PASS/FAIL, timestamp, operator/witness, destruction). Read-back words clear on every path.

**Independent audit (2026-06-28, historical — reviewed the v0.3 signed build) — testnet package PASSED on substance, verdict "No" only because it is the testnet/demo build.** Confirmed sound: crypto design + record verification *(then signed; the signature was removed in v0.4)*, byte-for-byte reproducible build, no localStorage/cookies/service-worker/external scripts, claim app free of any maker key, maker/QC bundles free of network refs, vectors reproduce + reject tampering. The "No" reduces to the known testnet→mainnet gate plus a punch-list, below.

**Mainnet build + final-audit checklist (from the independent audit's acceptance criteria):**
1. **Production maker key — ✅ N/A (removed in v0.4).** There is no maker signing key anymore — nothing to generate, air-gap, protect, or rotate. This item and the whole key ceremony are dropped. The maker tool is now a keyless card factory; the claim/maker/QC bundles contain no maker key of any kind.
2. **Mainnet config (P0). ✅ DONE 2026-07-01 — the build is now MAINNET.** `build/config.js` has `ACTIVE='mainnet'`: network byte `0x00`, `bc1` addresses, mainnet Esplora nodes + explorer; `core.js` and all apps read from it. Network labels are **dynamic** — the claim app shows a red "MAINNET · REAL BITCOIN" banner (never "no real money"), the maker/QC status lines show the network, and the mint script + print sheet stamp it. Verified: `test-core.mjs` on mainnet emits the correct `bc1` address (same witness program as the vector), all three apps rebuild with **no maker key**, and mainnet cards mint with network byte `0x00`. **Remaining before real cards ship:** host the mainnet claim app and set `APP_URL` for the QR; a small self-funded on-chain proof (fund a card with a few $ of real BTC, claim it); then, before selling to the public, the final audit + legal opinion.
3. **innerHTML / CSP (P1). ✅ DONE 2026-07-01.** `log()` (in `core.js`) and every claim-app render point (self-test, verify, broadcast — incl. node-supplied txid/errors) now use `textContent` + DOM-created spans, never `innerHTML`. `assemble.mjs` pins CSP `script-src` from `'unsafe-inline'` to the exact `sha256-` of the inlined bundle (`'unsafe-inline'` removed; hash confirmed to equal the inlined script so the app still loads).
4. **Remove setup autofill of Part 2 (P2). ✅ DONE 2026-07-01.** `genP2` no longer copies the buyer mnemonic into the claim field; the recipient re-enters the written words by hand at claim time.
5. **Serial integrity (P2).** _[pending]_ Replace the volatile in-memory serial counter (`let serialCounter = 1` in `app-maker.js`) with an operator-entered batch serial range / external monotonic manifest, so serials don't reset/collide across maker-tool sessions. (Best applied with the maker-tool/ceremony work.)
6. **Supply chain (P2). ✅ DONE 2026-07-01.** esbuild advisory (GHSA-67mh-4wv8-2f99) cleared: bumped esbuild `0.24.0 → 0.25.0` (`npm audit` = 0 vulnerabilities), lockfile updated, claim app rebuilt on it.

**Progress note (2026-07-01).** Items 3, 4, 6 implemented + verified against the testnet build; core crypto left untouched and re-verified by `build/test-core.mjs` (genuine card verifies, vector address + commutativity match, forged card rejected). The reviewer-suggested **fail-closed enum rejection is already present** in `parseAndVerifyCard` (unknown version/network/scripttype/kdf all throw; testnet `NETWORK=0x01` already rejects mainnet-flagged records). Of the remaining items: 1 became **N/A in v0.4** (no maker key exists), 2 is **DONE** (mainnet flipped 2026-07-01), and 5 (serial manifest) remains, pairing naturally with the manufacturing/QC tooling work. *(This note predates v0.4; the "maker-key ceremony that re-signs artifacts" it once referenced no longer exists.)*

**Second-review additions (2026-07-01) — gate to mainnet alongside the above:**
- **~~Sign the record directly~~ — MOOT.** v0.4 removed the maker signature entirely, so there is nothing to sign.
- **QR/delivery hardening (physical). _Partial — 2026-07-01._** A swapped-QR / counterfeit-app phishing card defeats in-band verification (the QR chooses the verifier). The card back now prints "opens bitcards.xyz only" next to the QR (`print/_buildsheet.py`) as the anti-swap tell. Remaining: finalize the real domain (currently a placeholder), print the published bundle hash, tamper-evident packaging over the QR, serial-lookup second channel. State the residual plainly (cryptography does not close it).
- **Recovery UX (physical + web). ✅ DONE — 2026-07-01 (web + card line).** Because the scalar is the BIP32 master key, the words do NOT work in a standard wallet. Published: `recover/recover.html` (plain-English 3-way recovery + the algorithm + the frozen vector to verify any tool) and `recover/bitcard-recover.py` (a **pure-stdlib**, no-install offline recovery tool — **verified to reproduce the frozen vector address, `d`, pubkey, commutativity, and an importable WIF**). The card back prints a **domain-free** self-describing line — "not a normal wallet seed: the two halves are one key (open standard)" (`print/_buildsheet.py`) — so **nothing on the card depends on a hosted site**. `recover/recover.html` is framed as one mirrored copy of an open standard (works offline; self-verifies against the frozen vector). **Durability = words + open method + any Bitcoin tool.** Remaining (no ongoing hosting): open-source the bundle (`.html` + `.py` + vectors + spec) and pin it to **Arweave** (pay-once, no renewal); a friendly domain, if used at all, is convenience-only for the *claim* flow, which degrades to recovery if it lapses.
- **Second seal over Part 2 (physical).** Part 2 sits in plaintext on the card back; add a buyer-applied seal over the written words so a photo of the back doesn't expose it (defense-in-depth; harmless if Part 1 is destroyed but narrows the window).
- **Manufacturing trust model (process).** If Part 1 is printed by a third party, require a vendor NDA + secure-deletion clause + certificate of destruction (or a secure personalization bureau); never retain a serial→Part-1 mapping. Frame the non-custodial claim accurately when a vendor is in the chain.

**Remaining before mainnet (release steps):**
1. Apply the mainnet checklist above to the source and build the mainnet artifacts.
2. **Content-address/pin** the audited mainnet build (IPFS + Arweave), publish full-file + bundle hashes, wire the QR.
3. **Final security sign-off** — re-run the independent audit against that exact mainnet package.

*(Optional, post-v1: a strict offline/online claim split offered as an "advanced" mode for high-value users — not required for the first batch.)*

---

## Appendix — notation
`·` = scalar·point; `+` on points = EC addition; `+` on scalars = addition mod `n`. Compressed pubkey = 33 bytes. `b64url` = base64url, no padding.
