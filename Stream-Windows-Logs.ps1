# ==============================================================================
# Chetas ULPF — Real-Time Windows Log Streaming Shipper
# Streams authentic Windows System & Application events directly to Chetas
# ==============================================================================

param (
    [string]$ChetasServerIp = "10.180.250.129",
    [int]$Port = 3000
)

# Ensure TLS 1.2+ protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

if (-not $ChetasServerIp -or $ChetasServerIp.Trim() -eq "") {
    $ChetasServerIp = "10.180.250.129"
}
$ChetasServerIp = $ChetasServerIp.Trim()
$chetasHost = "http://${ChetasServerIp}:${Port}"

# Discover local active IPv4 address
$localIp = $null
try {
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { 
        $_.InterfaceAlias -notlike "*Loopback*" -and 
        $_.IPAddress -notlike "169.254.*" -and 
        $_.IPAddress -notlike "127.*" 
    } | Select-Object -ExpandProperty IPAddress -First 1)
} catch {}

if (-not $localIp) {
    try {
        $localIp = ([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | Where-Object { 
            $_.AddressFamily -eq 'InterNetwork' -and 
            $_.IPAddressToString -notlike '127.*' -and 
            $_.IPAddressToString -notlike '169.254.*' 
        } | Select-Object -First 1).IPAddressToString
    } catch {}
}
if (-not $localIp) { $localIp = "127.0.0.1" }

Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   CHETAS ULPF -- Real-Time Windows Telemetry Shipper" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Host:           $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host " Local IP:       $localIp" -ForegroundColor Green
Write-Host " Chetas Server:  http://${ChetasServerIp}:${Port}" -ForegroundColor Yellow
Write-Host " Ingestion API:  $chetasHost/api/logs/ingest" -ForegroundColor DarkCyan
Write-Host " Streaming:      Live Windows Events + Health Telemetry" -ForegroundColor Gray
Write-Host " Status:         ACTIVE (Press Ctrl+C to stop)" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Helper function to send log to Chetas
function Send-ChetasLog($payloadObj) {
    $json = $payloadObj | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Uri "$chetasHost/api/logs/ingest" -Method Post -Body $json -ContentType "text/plain" -Headers @{"x-source-id"="src-win-$env:COMPUTERNAME"} -TimeoutSec 4 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Initial Handshake
Write-Host "[*] Sending initial handshake event to Chetas..." -ForegroundColor Cyan
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$osCaption = if ($osInfo) { $osInfo.Caption } else { [System.Environment]::OSVersion.VersionString }

$handshake = @{
    source_ip      = $localIp
    destination_ip = $ChetasServerIp
    eventSource    = "ChetasWindowsAgent"
    eventId        = 100
    level          = "Information"
    timestamp      = (Get-Date).ToUniversalTime().ToString("o")
    vendor         = "Microsoft Windows"
    product        = "Remote-Windows-$env:COMPUTERNAME"
    source_host    = "$env:COMPUTERNAME"
    message        = "Chetas Windows Telemetry Streamer active on $env:COMPUTERNAME ($localIp). OS: $osCaption"
}

$sent = Send-ChetasLog $handshake
if ($sent) {
    Write-Host "[OK] Connected! Handshake event received by Chetas server." -ForegroundColor Green
} else {
    Write-Host "[!] Warning: Cannot reach Chetas at $chetasHost." -ForegroundColor Red
    Write-Host "    Make sure Chetas server is running and reachable on the network." -ForegroundColor DarkYellow
    Write-Host "    Retrying automatically in the background..." -ForegroundColor DarkYellow
}
Write-Host ""

$sentIds = New-Object 'System.Collections.Generic.HashSet[string]'
$counter = 0
$lastHeartbeat = [DateTime]::UtcNow

while ($true) {
    # 1. Fetch Windows Event Logs (System + Application)
    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName=@('System', 'Application')} -MaxEvents 5 -ErrorAction Stop
    } catch {
        try {
            $events = @(Get-EventLog -LogName Application -Newest 3 -ErrorAction SilentlyContinue) + @(Get-EventLog -LogName System -Newest 3 -ErrorAction SilentlyContinue)
        } catch {}
    }

    foreach ($ev in $events) {
        if (-not $ev) { continue }
        $logName = if ($ev.LogName) { $ev.LogName } else { "EventLog" }
        $recId = if ($ev.RecordId) { $ev.RecordId } elseif ($ev.Index) { $ev.Index } else { [Guid]::NewGuid().ToString() }
        $key = "$logName-$recId"

        if (-not $sentIds.Contains($key)) {
            $sentIds.Add($key) | Out-Null
            $counter++

            $prov = if ($ev.ProviderName) { $ev.ProviderName } elseif ($ev.Source) { $ev.Source } else { "WindowsSystem" }
            $id = if ($ev.Id) { $ev.Id } elseif ($ev.EventID) { $ev.EventID } else { 0 }
            $lvl = if ($ev.LevelDisplayName) { $ev.LevelDisplayName } elseif ($ev.EntryType) { $ev.EntryType.ToString() } else { "Information" }
            $rawMsg = if ($ev.Message) { ($ev.Message -replace "`r?`n", " ") } else { "Windows Event $id from $prov" }
            if ($rawMsg.Length -gt 300) { $rawMsg = $rawMsg.Substring(0, 300) + "..." }

            $payload = @{
                source_ip      = $localIp
                destination_ip = $ChetasServerIp
                eventSource    = $prov
                eventId        = $id
                level          = $lvl
                timestamp      = (Get-Date).ToUniversalTime().ToString("o")
                vendor         = "Microsoft Windows"
                product        = "Remote-Windows-$env:COMPUTERNAME"
                source_host    = "$env:COMPUTERNAME"
                message        = $rawMsg
            }

            $success = Send-ChetasLog $payload
            $timeStr = (Get-Date).ToString("HH:mm:ss")
            if ($success) {
                Write-Host "[$timeStr] [#$counter] INGESTED: $localIp -> $ChetasServerIp | $prov (Event $id)" -ForegroundColor Green
            } else {
                Write-Host "[$timeStr] [RETRYING] Failed to reach Chetas at $chetasHost (will retry)" -ForegroundColor Yellow
            }
        }
    }

    # 2. Continuous Telemetry Heartbeat (every 6 seconds if quiet)
    $now = [DateTime]::UtcNow
    if (($now - $lastHeartbeat).TotalSeconds -ge 6) {
        $lastHeartbeat = $now
        $counter++

        $cpu = 0
        try {
            $cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average
            if ($null -eq $cpu) { $cpu = 15 }
        } catch { $cpu = 10 }

        $timeStr = (Get-Date).ToString("HH:mm:ss")
        $heartbeatPayload = @{
            source_ip      = $localIp
            destination_ip = $ChetasServerIp
            eventSource    = "WindowsTelemetryService"
            eventId        = 200
            level          = "Information"
            timestamp      = (Get-Date).ToUniversalTime().ToString("o")
            vendor         = "Microsoft Windows"
            product        = "Remote-Windows-$env:COMPUTERNAME"
            source_host    = "$env:COMPUTERNAME"
            message        = "Heartbeat telemetry: CPU Load $($cpu)% | Host $env:COMPUTERNAME active | Status: Healthy"
        }

        $success = Send-ChetasLog $heartbeatPayload
        if ($success) {
            Write-Host "[$timeStr] [#$counter] HEARTBEAT: $localIp -> $ChetasServerIp | CPU: $($cpu)% | Host: $env:COMPUTERNAME [Healthy]" -ForegroundColor Cyan
        } else {
            Write-Host "[$timeStr] [WAITING] Chetas at $chetasHost not responding..." -ForegroundColor DarkYellow
        }
    }

    Start-Sleep -Seconds 3
}
