# Security

This page states what Bitcard protects, what it does not, what has been tested, and how to report a problem. It is written to be checked, not believed: every protection listed here has a test in `build/` or a procedure in `MINT-RUNBOOK.md`.

## Reporting a vulnerability

If you have access to this repository, open an issue that says only that you have a security report and asks for a private channel; the maintainer will reply with one. Do not post exploit details in the issue. If you do not have repository access, use the contact address published at https://bitcards.xyz.

Please never use real customer card words while testing. Use the published test vectors in `spec/bitcard-test-vectors.json`, freshly generated throwaway keys, or Bitcoin Core regtest coins. Never broadcast test transactions on mainnet.

We aim to acknowledge reports within a few days. Fixes ship as a new release with updated published hashes, and the finding is recorded in the commit message and in `spec/bitcard-claim-history.md` when it changes the design.

## What the design protects

- **Nobody can spend with one half.** The spending key is the sum of two secp256k1 scalars derived from two 12-word phrases. Knowing one half reduces the problem to the discrete log of the other half's public key, which is 128-bit work.
- **Bitcard never holds a complete key.** Part 2 is generated on the buyer's device and never transmitted. Part 1 exists at the factory only until the card passes pairing QC, after which the maker copy is destroyed under witness (`MINT-RUNBOOK.md`, sections 7 to 9).
- **The card carries only public data.** The QR is a public record: version, network, script type, key-derivation id, the Part 1 public key and a serial. Record v2 adds a 5-byte checksum so a mistyped code is rejected instead of deriving an address nobody can open.
- **The apps can be verified.** Both HTML files are single self-contained pages with no external scripts, fonts, analytics or service workers. A fresh clone rebuilds them byte for byte; the SHA-256 of each is published in `README.md` and re-checked against the live site every hour.
- **The claim transaction is checked before and after signing.** Two independent public nodes must agree on the coins; the destination is confirmed on screen and compared again at send time; the signed transaction must pay the reviewed destination, its witness must match the card's key, and the node must echo the transaction id the app computed. Fees are capped and sanity-bounded. Replace-by-fee is enabled.
- **Recovery does not depend on Bitcard.** The specification, frozen vectors, a frozen Bitcoin Core-accepted transaction and a standard-library Python tool are in this repository so any competent implementer can reconstruct the key.

## Honest limits

- **The hosted page is a web wallet.** Claiming at `bitcards.xyz/app.html` trusts that the page you loaded is the genuine one. A compromised host or CDN could serve altered code. The published hash, the in-app fingerprint and the hourly monitor make substitution detectable; they do not make it impossible. The offline tool exists for people who do not want that trust.
- **A counterfeit card is a counterfeit card.** Cards are not signed (the format is deliberately permissionless). A fake card could carry a QR pointing at an attacker's page. Trusted distribution and tamper-evident packaging are the mitigation, exactly as for a paper voucher.
- **It is a bearer instrument.** Whoever holds the physical card and opens both seals controls the funds.
- **Part 2 alone can watch, not spend.** Someone who copies Part 2 and reads the public QR can compute the funding address and see its balance. They still cannot spend without Part 1.
- **Balance display trusts two nodes.** If both public nodes lie in the same way, the app can show a coin that does not exist; a spend of it fails at the network. Funds are not at risk, but the display can be wrong.
- **Entropy guards catch stuck generators, not subtle ones.** The setup flow refuses a missing, failing, constant or repeating random source. A generator that is deterministic yet varying is undetectable from inside a browser.
- **No algorithm agility on printed cards.** A card is bound to secp256k1, SHA-256, RIPEMD-160 and P2WPKH for its whole life. Recovery in twenty years assumes those stay computable and spendable and that a copy of the specification survives.
- **Software tests do not check physical cards.** Pairing of sealed words to the printed QR, destruction of maker copies and printer hygiene are controlled by the runbook and by named people, not by code.

## What has been tested

The release gate (`node test-all.mjs` in `build/`) runs 21 suites. Beyond ordinary unit tests they include:

- Derivation against the frozen vectors, including the case where the two scalars wrap past the curve order, and a differential check against a second implementation.
- A frozen signed transaction whose acceptance was obtained from an independent Bitcoin Core regtest node.
- Byte-for-byte reproduction of the released files from a clean tree.
- Driving the real built bundle through the claim and offline user interfaces, including races between card changes, destination edits and in-flight network responses.
- Hostile network behaviour: disagreeing nodes, fabricated coins, unreachable or hanging nodes, oversized or malformed responses, lying fee estimates.
- Record checksum rejection, entropy guards, mint guards and the serial ledger, and spec-to-code consistency.

External reviews in 2026 additionally ran mutation testing (each named defect must be caught by the unmodified gate), property-based state-machine testing with seeded sequences, record fuzzing, and end-to-end sweeps on Bitcoin Core regtest. Findings from those reviews and the fixes are in the commit history.

## Scope for researchers

In scope: `app/`, `build/` (including the mint, QC and release tooling), `recover/`, `print/`, `spec/` and `monitor/`. Reports about the specification itself are welcome, especially anything that would let a single half spend, let a corrupted record derive a valid-looking address, or let a compromised node move funds.

Out of scope: content of the marketing site, third-party wallets used to sweep, and denial of service against the public nodes the app queries.
