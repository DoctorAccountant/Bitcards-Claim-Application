# Bitcard — open standard + claim app (v0.4)

A physical, non-custodial bitcoin gift card. The card carries a key split into two halves of 12 words: one sealed under a scratch panel at manufacture, one written by the buyer at setup. Only someone holding both halves can spend. The issuer never holds a complete key, never touches funds, and this repository exists so that **the bitcoin on any card is recoverable forever, by anyone, with standard tools, even if every Bitcard service disappears.**

## What is in this repository

| Path | What it is |
|---|---|
| `app/claim-app.html` | The complete claim app: one self-contained HTML file. No external scripts, no server, no accounts. Runs from any host or from a saved local copy. |
| `recover/recover.html` | Plain-English recovery instructions (works offline). |
| `recover/bitcard-recover.py` | Offline recovery tool, Python standard library only. `python bitcard-recover.py --selftest` |
| `spec/bitcard-claim-spec.md` | The normative open standard: key scheme, card record format, flows, sweep rules. |
| `spec/bitcard-test-vectors.json` | Frozen test vectors. A correct implementation must reproduce them byte for byte. |
| `build/` | Full source + lockfile for reproducible builds of the app. |

## The trust model in one paragraph

Cards carry no issuer key and the app verifies no issuer signature (v0.4 removed it deliberately: this is an open, permissionless standard, like BIP39). A card QR is just `base64url` of a 41-byte public record. Funds are protected by the two-half key scheme, not by anything Bitcard controls. The app runs entirely on your device; your words never leave it. Network access is read-only lookups + transaction broadcast to two public bitcoin servers, which must agree with each other before the app trusts them.

## Verify the released app

```
sha256 of app/claim-app.html:
5fe13d290d410bd971d2a5d9c3ee32273044145f88e140f2afcdd5a3b8c11569
```

PowerShell: `Get-FileHash app/claim-app.html` · Linux/macOS: `shasum -a 256 app/claim-app.html`

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

You need both sets of 12 words from the card. Then either open any copy of the claim app, or run `recover/bitcard-recover.py`, or re-implement from the spec: each half is BIP39 (English, empty passphrase) → BIP32 master private key as a scalar; the spending key is `(d1 + d2) mod n` on secp256k1; the address is P2WPKH of the combined public key. Vectors in `spec/` verify any implementation.

**Copy this repository freely.** Redundant copies are what make the recovery promise permanent.
