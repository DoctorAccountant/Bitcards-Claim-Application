# Live-hash monitoring

`bitcard-hash-monitor.ps1` verifies all four hosted artifacts against `expected-hashes.json`. It writes runtime state to `%LOCALAPPDATA%\BitcardMonitor`, not into this Git checkout. `bitcard-monitor-watchdog.ps1` independently fails if the heartbeat is missing or more than two hours old.

The release operator must run both local scripts once after every deployment. The local schedule is a supplemental check only while its computer is awake: ordinary Windows sleep pauses it, so it must not be represented as continuous monitoring. A successful old heartbeat is not a current verdict. Inspect the scheduled task's last result as well as the heartbeat timestamp. If a second continuously available runner is required, install these scripts on an always-on machine.

The hourly GitHub workflow in `.github/workflows/live-hash-monitor.yml` is the primary continuous runner. It reads the committed expected hashes and fails visibly if any URL serves different bytes. The local check remains useful as an independently implemented post-deploy check, but a sleeping laptop is not a monitoring service. Repository or GitHub-account compromise could alter both the workflow and its expected values, so higher-assurance operations should place the second checker on an independent always-on account or host.
