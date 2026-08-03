# Bitcard: open standard + claim app (v0.4)

A physical, non-custodial bitcoin gift card. The card carries a key split into two halves of 12 words: one sealed under a scratch panel at manufacture, one written by the buyer at setup. Only someone holding both halves can spend. The issuer never holds a complete key and never touches funds. This repository exists so that **the bitcoin on any card is recoverable forever from the two word-halves, even if every Bitcard service disappears.** You recover with the open spec or the small included tool, which produces a standard private key (WIF); a standard wallet such as Sparrow or Electrum then **sweeps** it (Sweep, not Import).

## What is in this repository

| Path | What it is |
|---|---|
| `app/claim-app.html` | The complete claim app: one self-contained HTML file. No external scripts, no server, no accounts. Runs from any host or from a saved local copy. Convenience path, for small gifts. |
| `app/offline.html` | The offline tool, two modes, **no network code** (CSP `connect-src 'none'`): **set up a card** (generates the buyer's words and derives the deposit address on-device from the card's public QR data, so no website is involved in funding) and **open a card** (reconstructs the key as a WIF to sweep with a standard wallet). For larger amounts. Save it and run it offline. |
| `recover/recover.html` | Plain-English recovery instructions (works offline). |
| `recover/bitcard-recover.py` | Offline recovery tool, Python standard library only. `python bitcard-recover.py --selftest` |
| `spec/bitcard-claim-spec.md` | The normative open standard: key scheme, card record format, flows, sweep rules. |
| `spec/bitcard-test-vectors.json` | Frozen test vectors. A correct implementation must reproduce them byte for byte. |
| `build/` | Full source + lockfile for reproducible builds of the app. |

## The trust model in one paragraph

Cards carry no issuer key and the app verifies no issuer signature (v0.4 removed it deliberately: this is an open, permissionless standard, like BIP39). A card QR is just `base64url` of a 41-byte public record. Funds are protected by the two-half key, not by anything Bitcard controls. Your words never leave your device.

## What you must trust (and what you do not)

- **To recover funds: no operating Bitcard service is required.** The two word-halves plus the open method (or the included tool) reconstruct the key on any computer, offline. You do still trust, or independently verify, the recovery implementation you run, your own device, and the wallet you sweep into. This is the permanent guarantee.
- **To claim via the hosted web app (`bitcards.xyz/app.html`): you trust that you loaded the genuine app from the official address.** Like any web wallet, a compromised host could serve altered code that rebuilds the key inside the page. The published hash and the in-app code fingerprint let you check the program, but the real protection is loading it from a source you trust. This convenience path is meant for **small gifts.**
- **To avoid trusting website execution: use the offline key tool** (`app/offline.html`, or `bitcards.xyz/offline.html`). It contains no network code (its CSP is `connect-src 'none'`), reconstructs the key on your device, and hands it to a standard wallet's Sweep. Recommended for **larger amounts.** Note the honest limit: served live over HTTPS it is only as trustworthy as its delivery, so **the hosted page refuses word entry until you download it.** Save the file, verify its SHA-256 against the value published here, disconnect from the internet, then open the saved file (word entry unlocks under `file://`).

This is an **additive two-part key** (the two halves add to one ordinary key), not an on-chain multisig. It gives two-party control before claim and low fees; it does not provide on-chain multisig features (independent signing, timelocks, revocation).

## Verify the released app

```
sha256 of app/claim-app.html:
7ffbc74667bcd4de1c8bf7c9f2b90dd67591325455ac05ef62c7ba3fc1f139e7
sha256 of app/offline.html:
3759ec31bcfdf9d35164fe3231611f01c8082d2faac678d89081002e82a89f4e
```

PowerShell: `Get-FileHash app/claim-app.html` / Linux/macOS: `shasum -a 256 app/claim-app.html`

The same file is deployed at https://bitcards.xyz/app.html and must hash identically. The app also displays a runtime fingerprint of its own inline script (open "Is this app genuine?" at the bottom of the page).

## Rebuild it yourself

```
cd build
npm ci
npx esbuild app-claim.js --bundle --format=iife --minify --charset=ascii --target=es2020 --outfile=app-claim.bundle.js
node assemble.mjs template-claim.html app-claim.bundle.js claim-app.html
node test-core.mjs        # must print CORE OK
node test-hardening.mjs   # must print HARDENING OK
```

## Recover funds without any Bitcard service

You need both sets of 12 words from the card. Best: run `recover/bitcard-recover.py` (Python standard library only) or open the offline key tool, either of which reconstructs the key on your device with no network. Or re-implement from the spec: each half is BIP39 (English, empty passphrase) turned into a BIP32 master private key used **directly as a scalar** (nonstandard, which is why an ordinary wallet cannot recover from either phrase alone); the spending key is `(d1 + d2) mod n` on secp256k1; the address is P2WPKH of the combined public key. The recovered key is a standard WIF: **sweep** it with Electrum or Sparrow (use Sweep, not Import). Vectors in `spec/` verify any implementation.

**Copy this repository freely.** Redundant copies are what make the recovery promise permanent.
