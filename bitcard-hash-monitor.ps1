# Bitcard live-hash monitor (threat model section 5 / SOP-4).
# Fetches every live artifact URL and compares its SHA-256 against monitor/expected-hashes.json.
# On ANY mismatch: writes an ALERT file to the Desktop, pops a blocking warning, and logs.
# On success: appends one line to the log. Designed to run hourly via Windows Task Scheduler.
# Contains no secrets. If a mismatch is real, follow SOP-4 incident response: roll back the deploy, rotate credentials.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg = Get-Content (Join-Path $here "expected-hashes.json") -Raw | ConvertFrom-Json
$log = Join-Path $here "monitor-log.txt"
$stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

# HEARTBEAT: written on every run to a cloud-synced folder, so it is readable from a phone.
# Silence is itself the alarm. A monitor that only shouts on failure cannot tell you it stopped running,
# and an attacker who deploys while the workstation is off would otherwise meet no alarm at all.
# Contains no secrets: a timestamp, a verdict, and the release commit being watched.
$heartbeat = Join-Path $here "HEARTBEAT.txt"
function Write-Heartbeat($verdict, $detail) {
  $age = "checked $stamp"
  $txt = "Bitcard integrity check`r`n$age`r`nverdict: $verdict`r`nwatching: $($cfg.releaseCommit)`r`n$detail`r`n`r`n" +
         "If the timestamp above is more than a few hours old, the monitor is NOT running and the live site is unwatched."
  try { Set-Content -Path $heartbeat -Value $txt -Encoding UTF8 } catch {}
}

$failures = @()
$netErrors = @()

foreach ($u in $cfg.urls) {
    $name = ($u -split "/")[-1]
    $expected = $cfg.artifacts.$name
    if (-not $expected) { continue }
    try {
        $tmp = Join-Path $env:TEMP ("bhm-" + [IO.Path]::GetRandomFileName())
        Invoke-WebRequest -Uri $u -OutFile $tmp -UseBasicParsing -TimeoutSec 30 | Out-Null
        $h = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
        Remove-Item $tmp -Force
        if ($h -ne $expected.ToLower()) { $failures += "$u served $h (expected $expected)" }
    } catch {
        $netErrors += "$u unreachable: $($_.Exception.Message)"
    }
}

if ($failures.Count -gt 0) {
    $msg = "BITCARD ALERT $stamp`r`n`r`nLIVE FILE DOES NOT MATCH THE PUBLISHED HASH. Treat as possible compromise.`r`n`r`n" +
           ($failures -join "`r`n") + "`r`n`r`n" +
           "SOP-4 incident response: roll back the Vercel deployment NOW, rotate Vercel/Cloudflare credentials, do not resume until the cause is known.`r`n" +
           "(If this was a PLANNED release, update monitor/expected-hashes.json as the release SOP requires.)"
    $alertPath = Join-Path ([Environment]::GetFolderPath("Desktop")) ("BITCARD-ALERT-" + (Get-Date).ToString("yyyyMMdd-HHmmss") + ".txt")
    Set-Content -Path $alertPath -Value $msg -Encoding UTF8
    Add-Content -Path $log -Value "$stamp  MISMATCH  $($failures -join ' | ')"
    Write-Heartbeat "MISMATCH - POSSIBLE COMPROMISE" ($failures -join "`r`n")
    try { (New-Object -ComObject WScript.Shell).Popup($msg, 0, "BITCARD HASH ALERT", 48) | Out-Null } catch {}
    exit 2
} elseif ($netErrors.Count -gt 0) {
    # unreachable is logged but not alarmed: transient outages are common and cannot alter served bytes
    Add-Content -Path $log -Value "$stamp  UNREACHABLE  $($netErrors -join ' | ')"
    Write-Heartbeat "unreachable (transient, not an alarm)" ($netErrors -join "`r`n")
    exit 1
} else {
    Add-Content -Path $log -Value "$stamp  OK  all $($cfg.urls.Count) artifacts match ($($cfg.releaseCommit))"
    Write-Heartbeat "OK" "all $($cfg.urls.Count) live artifacts match the published hashes"
    exit 0
}
