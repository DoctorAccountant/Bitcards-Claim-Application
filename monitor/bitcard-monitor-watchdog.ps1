# Alerts if the live-hash monitor has not successfully started within the expected interval.
# Schedule this independently of bitcard-hash-monitor.ps1 so a broken monitor cannot certify itself.

$ErrorActionPreference = "Stop"
$stateDir = Join-Path $env:LOCALAPPDATA "BitcardMonitor"
$heartbeat = Join-Path $stateDir "HEARTBEAT.txt"
$maxAge = [TimeSpan]::FromHours(2)
$stale = (-not (Test-Path -LiteralPath $heartbeat)) -or (((Get-Date) - (Get-Item -LiteralPath $heartbeat).LastWriteTime) -gt $maxAge)

if ($stale) {
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $msg = "BITCARD MONITOR STALE $stamp`r`n`r`nThe live-hash monitor heartbeat is missing or more than two hours old. Do not rely on its last verdict. Repair the scheduled task and independently verify the live hashes."
    $alertPath = Join-Path ([Environment]::GetFolderPath("Desktop")) ("BITCARD-MONITOR-STALE-" + (Get-Date).ToString("yyyyMMdd-HHmmss") + ".txt")
    Set-Content -Path $alertPath -Value $msg -Encoding UTF8
    try { (New-Object -ComObject WScript.Shell).Popup($msg, 300, "BITCARD MONITOR STALE", 48) | Out-Null } catch {}
    exit 2
}

exit 0
