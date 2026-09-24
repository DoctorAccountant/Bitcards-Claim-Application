# Release procedure

A release is the pair of customer-facing files `app/claim-app.html` and `app/offline.html`, plus the manufacturing tool `print/qc-tool.html`. A release is not complete when the local tests pass. Every step below must be recorded as successful before the release is announced or funded against.

## Before publishing

1. **Rebuild from a fresh clone of the exact source commit.** In `build/`, run `npm ci`, then the three documented builds in `README.md` ("Rebuild it yourself"), then `node test-all.mjs`. Require `ALL SUITES PASSED` and require the rebuilt files to equal the committed artifacts byte for byte. A dirty working tree or a hash difference stops the release.
2. **Deploy those exact committed artifacts.** Do not rebuild inside the hosting service and do not copy from another working tree.
3. **Stamp and verify the live site.** Run `node build/release-finish.mjs --commit <source-commit>`. It fetches all four production and mirror URLs, compares each to the locally built file, rewrites the published hashes in `README.md` and `monitor/expected-hashes.json`, and fails on any mismatch. Commit the stamped files.
4. **Check issued cards still work.** Run `node build/test-live-real-cards.mjs <manifest>` for every issued-card QC manifest available to the release operator. This confirms that the deployed app still recognises and correctly derives every card already in circulation.
5. **Confirm monitoring.** Run the local live-hash monitor once and require a fresh successful result. Confirm the hourly GitHub workflow (`.github/workflows/live-hash-monitor.yml`) is enabled and its latest run is green. The GitHub workflow is the continuous runner; the local scheduled task is supplemental and pauses while its computer sleeps. A stale local heartbeat is not evidence that the site is unchanged.

## After publishing

- The monitor compares the live bytes at every URL in `monitor/expected-hashes.json` against the stamped hashes every hour. A mismatch is a release incident: take the page down or restore the correct bytes, then investigate before doing anything else.
- The README hash block is parsed by `build/release-metadata.mjs`. Keep the exact format `sha256 of app/<file>:` followed by the hash on the next line, or the release gate fails closed.
- Production minting and printer acceptance are governed by `MINT-RUNBOOK.md`. Passing this software gate never replaces those physical controls.

## What "reproducible" means here

The build depends only on files committed in this repository: the source, the pinned `package-lock.json`, and the vendored fonts under `build/assets/`. `build/test-build-portability.mjs` is the first suite in the gate and fails if the rebuilt files differ from the committed ones. Anyone with the repository and Node.js can therefore confirm that the published hash corresponds to the published source.
