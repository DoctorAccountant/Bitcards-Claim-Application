# Bitcard production mint runbook

This is the required order of operations for every production print batch. It is intentionally separate from the cryptographic specification: the specification defines what a card means; this runbook controls how Bitcard produces cards without retaining or mispairing Part 1.

## Roles and records

- Name one release operator, one QC operator and one witness. The QC operator or witness must independently compare the physical card with the public manifest; the person who ran the mint must not be the only checker.
- Part 1 words and any CSV containing them are secret production material. They must never enter OneDrive, Dropbox, Google Drive, email, chat, git, ticketing systems, screenshots or ordinary logs.
- The QC manifest, audit JSON, hashes, serial ledger and count/reconciliation records contain public data and must be retained.
- Stop on any mismatch, unexplained count, reused serial, failed self-test, missing file or uncertain destruction status. Do not repair a row manually.

## 1. Freeze and verify the release

1. Select and record the exact release commit that will create the batch.
2. In a fresh clone, enter `build/`, run `npm ci`, execute the three documented builds in `README.md`, then run `node test-all.mjs`.
3. Require `ALL SUITES PASSED` and a clean working tree after comparing the rebuilt artifacts. Confirm `print/qc-tool.html` opens locally and its self-test says PASS.
4. Record the release commit and hashes. Do not mint from a working tree with unrelated or uncommitted changes.

## 2. Reserve the serial range before generating keys

1. Choose an unused, contiguous range. Never reuse a serial, including a range from an abandoned or crashed run.
2. Add the exact range to `build/serial-allocations.json` with state `reserved-for-mint`, its batch/SKU purpose and the intended count.
3. Review the ledger for overlap, commit the reservation and push it before running the mint. The committed ledger is the coordination point between people and machines.

## 3. Prepare the mint station

1. Use a trusted, fully updated computer. Disconnect it from networks for key generation and close cloud-sync, remote-access, clipboard-history, screen-capture and messaging software.
2. Choose a new output directory on a non-synced local or encrypted removable drive. Do not put it inside this repository.
3. Ensure only the mint operator can access the output and that the printer handoff method is ready before secrets are generated.

## 4. Mint once

From `build/`, run with all arguments explicit:

```text
node mint-pilot-csv.mjs <COUNT> <START_SERIAL> <NON_SYNCED_OUTPUT_DIRECTORY>
```

The requested range must exactly match the committed `reserved-for-mint` ledger entry. The script changes it to `allocated` before generating any key. If the process then fails or the computer loses power, keep that range allocated and retire it; never change it back for reuse.

Require the printed summary to show the intended count, unique serials, unique Part 1 keys and a complete words-to-QR match. Record the CSV SHA-256 without copying any words into the record. Commit and push the ledger's resulting `allocated` state.

## 5. Prepare and independently verify the printer file

If the printer requires a SKU column or several mint outputs must be combined, use:

```text
node merge-pilot-csv.mjs <NEW_PRINTER_CSV> <SKU_PREFIX> <MINT_CSV> [MORE_MINT_CSV_FILES]
```

The output filename must not already exist. Then verify the exact CSV that will go to print against its matching public manifest:

```text
node verify-printed-batch.mjs <PRINTER_CSV> <QC_MANIFEST_JSON>
```

Require every count to equal the row count and require `BATCH VERIFIED`. Record the exact printer CSV hash and total rows. A later file with a different hash is a different print job and must not be accepted under this record.

## 6. Transfer and print

1. Send the exact hashed printer CSV through an approved encrypted channel to a named recipient. Send its password or key through a different channel.
2. Require the printer to protect variable-data files, spoilage, plates, caches, backups and machine storage as secret material, and to confirm deletion after acceptance.
3. The printer must keep each row together: serial, SKU if used, Part 1 words and QR from one CSV row must land on the same physical card. Sorting or separately merging columns is prohibited.
4. Produce a setup proof before the run. Confirm dimensions, contrast, QR quiet zone, scratch coverage and that multiple representative QRs scan from the physical stock. Do not fund proof cards.

## 7. Perform 100% pre-seal pairing QC

On a station separate from the mint station, open the committed `print/qc-tool.html` locally and keep the station offline.

For every card, while Part 1 is still visible and before applying the scratch panel:

1. Enter the operator and witness IDs.
2. Read the 12 words from the physical card; do not paste them from the CSV.
3. Scan the QR from that same physical card into the tool.
4. Require MATCH. A MISMATCH quarantines the entire batch until its cause is established; do not simply re-run or replace that card.
5. Apply the scratch panel, destroy the corresponding maker copy and record the destruction sign-off.
6. Export and safely retain the public audit JSON frequently and at the end of the batch. The page does not retain an audit across a reload or closed tab until it has been exported.

Do not ship if any card is missing, duplicated, failed, awaiting destruction sign-off, or has an unset operator/witness.

## 8. Reconcile and destructively sample the finished batch

1. Reconcile the delivered card count, serials and SKUs against the public manifest and printer job record. Investigate every extra, missing or duplicate item, including spoilage.
2. Randomly select at least 5 cards per 300 from across the finished run. Reveal their scratch panels, scan the physical QRs and repeat the word-to-QR check. These samples and their secrets are destroyed and can never be sold.
3. One sample mismatch quarantines the full batch. Determine and document the cause before any release decision.
4. Record the sample serials, result, operator, witness and destruction. Never record their words.

## 9. Destroy production secrets and release the batch

Only after all physical QC and reconciliation pass:

1. Obtain documented deletion/destruction confirmation for the printer's CSV copies, caches, backups, spoilage and waste.
2. Destroy the mint station's secret CSVs and temporary copies. Account for removable media and backups. Retain no Part 1 words.
3. Retain the public QC manifest, QC audit JSON, hashes, serial ledger, printer reconciliation, destructive-sample record and destruction sign-offs.
4. A named human release approver reviews the complete record and marks the batch accepted. Software tests alone cannot approve physical cards.

## Abort rules

Quarantine the batch and stop if any of the following occurs: a test or self-test fails; the release tree is not the recorded commit; a serial is unreserved or duplicated; a CSV or manifest hash changes; words do not match the QR; serial/SKU/count reconciliation fails; a sample fails; secret material reaches a synced or uncontrolled system; printer deletion is uncertain; or the maker copy cannot be proven destroyed.
