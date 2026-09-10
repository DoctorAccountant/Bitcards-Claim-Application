# Live-hash monitoring

`bitcard-hash-monitor.ps1` verifies all four hosted artifacts against `expected-hashes.json`. It writes runtime state to `%LOCALAPPDATA%\BitcardMonitor`, not into this Git checkout. `bitcard-monitor-watchdog.ps1` independently fails if the heartbeat is missing or more than two hours old.

The release operator must run both scripts once after every deployment, then schedule the hash monitor hourly and the watchdog hourly on a different minute. A successful old heartbeat is not a current verdict. Inspect the scheduled task's last result as well as the heartbeat timestamp.

The GitHub workflow in `.github/workflows/live-hash-monitor.yml` is an infrastructure-independent second runner. It reads the committed expected hashes and fails visibly if any URL serves different bytes. It does not replace the local watchdog: repository or GitHub-account compromise could alter both the workflow and its expected values.
