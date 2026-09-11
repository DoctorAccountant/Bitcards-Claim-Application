# Bitcard: open standard + claim app (v0.4)

A physical, non-custodial bitcoin gift card. The card carries a key split into two halves of 12 words: one sealed under a scratch panel at manufacture, one written by the buyer at setup. Only someone holding both halves can spend. The issuer never holds a complete key and never touches funds. The two word-halves contain everything needed to reconstruct the key without any Bitcard service, provided the words, open specification and compatible recovery software are preserved. The included tool produces a standard private key (WIF), which a wallet then **sweeps** using the card's P2WPKH/native-SegWit source type (Sweep, not Import).

## What is in this repository

| Path | What it is |
|---|---|
| `app/claim-app.html` | The complete claim app: one self-contained HTML file. No external scripts, no server, no accounts. Runs from any host or from a saved local copy. The normal path: scan the card and claim in a couple of taps. |
| `app/offline.html` | The offline tool, two modes, **no network code** (CSP `connect-src 'none'`): **set up a card** (generates the buyer's words and derives the deposit address on-device from the card's public QR data, so no website is involved in funding) and **open a card** (reconstructs the key as a WIF to sweep with a standard wallet). For anyone who prefers not to depend on a website. Save it and run it offline. |
| `recover/recover.html` | Plain-English recovery instructions (works offline). |
| `recover/bitcard-recover.py` | Offline recovery tool, Python standard library only; targets Python 3.7+. Run `python bitcard-recover.py --selftest` on the exact runtime you intend to use. |
| `spec/bitcard-claim-spec.md` | The normative open standard: key scheme, card record format, flows, sweep rules. |
| `spec/bitcard-claim-history.md` | Non-normative design history, kept separate so retired signature/status text cannot be mistaken for current requirements. |
| `spec/bitcard-test-vectors.json` | Frozen test vectors. A correct implementation must reproduce them byte for byte. |
| `spec/bitcard-signed-transaction-vector.json` | Frozen transaction accepted by an independent Bitcoin Core regtest, including prevout, script, amount, txid and BIP143 digest. |
| `build/serial-allocations.json` | Versioned serial-range ledger. A production mint requires an exact pre-reserved range and marks it allocated before generating keys. |
| `build/` | Full source, vendored font inputs, lockfile, production CLI mint, and release gates. Browser minting is deliberately disabled. |

## The trust model in one paragraph

Cards carry no issuer key and the app verifies no issuer signature (v0.4 removed it deliberately: this is an open, permissionless standard, like BIP39). A card QR is just `base64url` of a public record: 41 bytes (record v1, the 2026 pilot cards) or 46 bytes (record v2, all later cards, which append a 5-byte SHA-256 checksum so a mistyped card code is rejected instead of silently addressing funds to a key nobody holds). Claim and recovery retain both formats. Because v1 cannot check itself, the official apps allow v1 funding/setup only for an exact issued-record match; unknown v1 records remain claimable when their Part 1 words reproduce P1. Funds are protected by the two-half key, not by anything Bitcard controls. Your words never leave your device.

## What you must trust (and what you do not)

- **To recover funds: no operating Bitcard service is required.** The two word-halves plus the preserved open method (or the included tool) reconstruct the key offline. You still trust, or independently verify, the recovery implementation, device and destination wallet. Preserve redundant verified copies and periodically test the published vectors; no software or storage medium can honestly be guaranteed for an unlimited future.
- **To claim via the hosted web app (`bitcards.xyz/app.html`): you trust that you loaded the genuine app from the official address.** Like any web wallet, a compromised host could serve altered code that rebuilds the key inside the page. The published hash and the in-app code fingerprint let you check the program, but the real protection is loading it from a source you trust. This is the normal path, and it carries the same delivery trust as any web wallet or banking site.
- **To avoid trusting website execution: use the offline key tool** (`app/offline.html`, or `bitcards.xyz/offline.html`). It contains no network code (its CSP is `connect-src 'none'`), reconstructs the key on your device, and hands it to a standard wallet's Sweep. Recommended for anyone who would rather not depend on a website at all. Note the honest limit: served live over HTTPS it is only as trustworthy as its delivery, so **the hosted page refuses word entry until you download it.** Save the file, verify its SHA-256 against the value published here, disconnect from the internet, then open the saved file (word entry unlocks under `file://`).

This is an **additive two-part key** (the two halves add to one ordinary key), not an on-chain multisig. It gives two-party control before claim and low fees; it does not provide on-chain multisig features (independent signing, timelocks, revocation).

## Verify the released app

```
sha256 of app/claim-app.html:
d869ba27041edf3d023e3bcdb72079e342896ba03adaf4ac0bf987a8e0ffa665
sha256 of app/offline.html:
537a011b908e232dc099d5d637006131b1cf7eaf437b9a3769aad391c0c47ba7
```

PowerShell: `Get-FileHash app/claim-app.html` / Linux/macOS: `shasum -a 256 app/claim-app.html`

The same file is deployed at https://bitcards.xyz/app.html and must hash identically. The app also displays a runtime fingerprint of its own inline script (open "Is this app genuine?" at the bottom of the page).

## Rebuild it yourself

The build reads only files committed in this repository. It does not require fonts or other assets from a developer's machine.

```
cd build
npm ci                    # on Windows PowerShell use npm.cmd / npx.cmd
npx esbuild app-claim.js --bundle --format=iife --minify --charset=ascii --target=es2020 --outfile=app-claim.bundle.js
node assemble.mjs template-claim.html app-claim.bundle.js claim-app.html
npx esbuild app-offline.js --bundle --format=iife --minify --charset=ascii --target=es2020 --outfile=app-offline.bundle.js
node assemble.mjs template-offline.html app-offline.bundle.js offline.html
node test-all.mjs         # must print ALL SUITES PASSED
```

## Release procedure

A release is not complete when the local tests pass. Before publishing customer-facing bytes:

1. From a fresh clone of the exact source commit, run `npm ci`, rebuild both HTML files with the commands above, run `node test-all.mjs`, and require the rebuilt hashes to equal the committed files in `app/` byte for byte.
2. Deploy those exact two committed artifacts. Do not rebuild inside the hosting service or copy from another working tree.
3. Run `node build/release-finish.mjs --commit <source-commit>`. It must verify all four production and mirror URLs, rewrite the published hashes and monitor configuration, and fail on any mismatch.
4. Run `node build/test-live-real-cards.mjs <manifest>` for every issued-card manifest available to the release operator.
5. Run the local live-hash monitor once, require a fresh successful heartbeat and a successful scheduled-task result, and confirm the independent GitHub monitor is enabled. Treat a stale monitor as a release failure, not as evidence that the site is unchanged.

Do not announce or fund against a release until every applicable step is recorded as successful.

## Recover funds without any Bitcard service

You need both sets of 12 words from the card. Best: run `recover/bitcard-recover.py` (Python standard library only) or open the offline key tool, either of which reconstructs the key on your device with no network. Or re-implement from the spec: each half is BIP39 (English, empty passphrase) turned into a BIP32 master private key used **directly as a scalar** (nonstandard, which is why an ordinary wallet cannot recover from either phrase alone); the spending key is `(d1 + d2) mod n` on secp256k1; the address is P2WPKH of the combined public key. The recovered key is a standard WIF. In Sparrow Sweep, select **P2WPKH / Native SegWit**. In Electrum, enter `p2wpkh:` immediately before the WIF. Before confirming, require the wallet's source address to equal the recovered `bc1q...` address. Keep both halves until the sweep confirms and that address shows zero. Vectors in `spec/` verify any implementation.

**Copy this repository freely.** Redundant, periodically verified copies make the recovery design resilient to a website or company disappearing.
