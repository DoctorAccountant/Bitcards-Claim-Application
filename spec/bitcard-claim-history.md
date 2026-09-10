# Bitcard claim-spec history (non-normative)

This file preserves design history only. Implementations must follow `bitcard-claim-spec.md`; nothing here changes its requirements.

## v0.2–v0.3

Early drafts used an issuer signature (first BIP340, then Ed25519) over the card record. Those drafts also introduced the fixed-width record, P2WPKH output, manufacturing read-back/destruction ceremony, reproducible build inputs, app hash display, multi-node UTXO and broadcast handling, destination confirmation, fee bounds, and the recovery vectors.

The signature was removed in v0.4. It did not protect funds from a malicious app selected by a counterfeit QR, introduced a long-lived issuer key, and conflicted with a permissionless format. References in old reports to `sig(64)`, a 105-byte payload, signed-QR verification, or a maker signing-key ceremony describe those retired drafts.

## v0.4

The unsigned record became authoritative. Record v1 is the original 41-byte format. Record v2 adds a five-byte truncated SHA-256 integrity checksum and is required for new cards. The official apps retain claim/recovery compatibility for v1, but only allow new funding of v1 records that exactly match the public table of Bitcard-issued pilot records.

The hosted app remains the convenience path and trusts delivery of the page. The saved `offline.html` tool is the reduced-trust setup/recovery path. Browser minting was later retired in favor of the CLI mint plus a versioned serial-allocation ledger.

Dates, audit outcomes, deployed hashes, mirror identifiers, and operational launch status belong in release records because they change independently of this protocol document.
