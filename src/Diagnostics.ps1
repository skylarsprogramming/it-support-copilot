# Diagnostics.ps1 - read-only Windows troubleshooting checks

function Get-NetworkChecks {
    $checks = @()
    $cfg = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
        Select-Object -First 1

    if (-not $cfg) {
        $checks += New-Check 'Network' 'Network connection' Red 'No active network adapter with a gateway. Wi-Fi may be off, the cable unplugged or airplane mode on.'
        return $checks
    }
    $adapter = $cfg.InterfaceAlias
    $checks += New-Check 'Network' 'Network connection' Green "Adapter '$adapter' is connected."

    # IP address
    $ip = @($cfg.IPv4Address.IPAddress)[0]
    if ($ip -like '169.254.*') {
        $checks += New-Check 'Network' 'IP address' Red "Address $ip is a fallback address: the router did not assign an address (DHCP)."
    } else {
        $checks += New-Check 'Network' 'IP address' Green "The laptop has the address $ip."
    }

    # Router
    $gw = $cfg.IPv4DefaultGateway.NextHop
    if (Test-Connection -TargetName $gw -Count 2 -Quiet -TimeoutSeconds 2) {
        $checks += New-Check 'Network' 'Router (gateway)' Green "The router $gw answers."
    } else {
        $checks += New-Check 'Network' 'Router (gateway)' Yellow "The router $gw does not answer ping. Some routers block ping, so this alone is not an error."
    }

    # DNS: ask the configured server directly so the local cache cannot hide a problem
    $dnsServers = @((Get-DnsClientServerAddress -InterfaceAlias $adapter -AddressFamily IPv4).ServerAddresses)
    $dnsText = if ($dnsServers.Count) { $dnsServers -join ', ' } else { 'none' }
    try {
        Resolve-DnsName -Name 'www.microsoft.com' -Server $dnsServers[0] -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
        $checks += New-Check 'Network' 'DNS' Green "Website names resolve. DNS server: $dnsText."
    } catch {
        $checks += New-Check 'Network' 'DNS' Red "Website names cannot be resolved with DNS server $dnsText. Websites will not open although the network is connected."
    }

    # Internet
    try {
        $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -TimeoutSec 5 -ErrorAction Stop
        if ($r.Content -match 'Microsoft Connect Test') {
            $checks += New-Check 'Network' 'Internet' Green 'The internet is reachable.'
        } else {
            $checks += New-Check 'Network' 'Internet' Yellow 'A login page answered instead of the internet (for example hotel or train Wi-Fi).'
        }
    } catch {
        $checks += New-Check 'Network' 'Internet' Red 'The internet is not reachable.'
    }

    # Wi-Fi signal (skipped on cable)
    $line = netsh wlan show interfaces 2>$null | Select-String -Pattern '^\s*Signal\s*:\s*(\d+)\s*%'
    if ($line) {
        $sig = [int]$line.Matches[0].Groups[1].Value
        $st = if ($sig -ge 60) { 'Green' } elseif ($sig -ge 35) { 'Yellow' } else { 'Red' }
        $checks += New-Check 'Network' 'Wi-Fi signal' $st "Wi-Fi signal strength is $sig %."
    } else {
        $checks += New-Check 'Network' 'Wi-Fi signal' Green 'Not connected via Wi-Fi (cable or no Wi-Fi adapter).'
    }
    return $checks
}

function Get-SystemChecks {
    $checks = @()
    $os = Get-CimInstance Win32_OperatingSystem

    # Disk space
    $c = Get-PSDrive -Name C
    $total = $c.Used + $c.Free
    $pct = [math]::Round(100 * $c.Free / $total)
    $freeGB = [math]::Round($c.Free / 1GB, 1)
    $st = if ($pct -lt 10) { 'Red' } elseif ($pct -lt 20) { 'Yellow' } else { 'Green' }
    $checks += New-Check 'System' 'Disk space C:' $st "$freeGB GB free ($pct %)."

    # Memory
    $used = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize))
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $st = if ($used -gt 90) { 'Red' } elseif ($used -ge 80) { 'Yellow' } else { 'Green' }
    $checks += New-Check 'System' 'Memory' $st "$used % of $totalGB GB memory in use."

    # Uptime
    $days = [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalDays)
    $st = if ($days -ge 30) { 'Red' } elseif ($days -ge 7) { 'Yellow' } else { 'Green' }
    $checks += New-Check 'System' 'Uptime' $st "Last restart $days day(s) ago."

    # Windows updates
    $last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($last) {
        $age = ((Get-Date) - $last.InstalledOn).Days
        $st = if ($age -gt 60) { 'Red' } elseif ($age -gt 35) { 'Yellow' } else { 'Green' }
        $checks += New-Check 'System' 'Windows updates' $st "Last update ($($last.HotFixID)) installed $age day(s) ago."
    } else {
        $checks += New-Check 'System' 'Windows updates' Yellow 'The update history could not be read.'
    }
    return $checks
}

function Get-SecurityChecks {
    $checks = @()

    # Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.AntivirusEnabled -or -not $mp.RealTimeProtectionEnabled) {
            $checks += New-Check 'Security' 'Defender' Red 'Microsoft Defender real-time protection is off.'
        } elseif ($mp.AntivirusSignatureAge -gt 3) {
            $checks += New-Check 'Security' 'Defender' Yellow "Defender is on, but virus definitions are $($mp.AntivirusSignatureAge) days old."
        } else {
            $checks += New-Check 'Security' 'Defender' Green 'Defender real-time protection is on and definitions are current.'
        }
    } catch {
        $checks += New-Check 'Security' 'Defender' Yellow 'Defender status unavailable. Another antivirus product may be installed.'
    }

    # Firewall
    $off = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' })
    if ($off.Count) {
        $checks += New-Check 'Security' 'Firewall' Red "The firewall is off for: $($off.Name -join ', ')."
    } else {
        $checks += New-Check 'Security' 'Firewall' Green 'The firewall is on for domain, private and public networks.'
    }

    # BitLocker (reading it needs admin rights)
    try {
        $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On') {
            $checks += New-Check 'Security' 'BitLocker' Green 'Drive C: is encrypted.'
        } else {
            $checks += New-Check 'Security' 'BitLocker' Red 'Drive C: is not encrypted. If the laptop is stolen, all data can be read.'
        }
    } catch {
        $checks += New-Check 'Security' 'BitLocker' Yellow 'Not checked: needs administrator rights, or not available on Windows Home.'
    }

    # Local administrators (SID works on German and English Windows)
    try {
        $n = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop).Count
        $st = if ($n -le 2) { 'Green' } else { 'Yellow' }
        $checks += New-Check 'Security' 'Local administrators' $st "$n account(s) have administrator rights."
    } catch {
        $checks += New-Check 'Security' 'Local administrators' Yellow 'The administrator group could not be read.'
    }
    return $checks
}

function Invoke-Diagnostics {
    param(
        [string]$ScenarioFile,
        [string]$Language = 'English',
        [switch]$NoAI,
        [string]$OutFile = (Join-Path $PSScriptRoot "..\reports\troubleshoot-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
    )
    Write-Host 'Checking network...' -ForegroundColor Cyan
    $checks = @(Get-NetworkChecks)
    Write-Host 'Checking system...' -ForegroundColor Cyan
    $checks += Get-SystemChecks
    Write-Host 'Checking security...' -ForegroundColor Cyan
    $checks += Get-SecurityChecks

    # Test mode: replace chosen checks with simulated results from a JSON file
    if ($ScenarioFile) {
        $fake = @(Get-Content $ScenarioFile -Raw | ConvertFrom-Json)
        $checks = @($checks | ForEach-Object {
            $cur = $_
            $m = $fake | Where-Object { $_.Check -eq $cur.Check } | Select-Object -First 1
            if ($m) { New-Check $m.Category $m.Check $m.Status "$($m.Detail) (simulated)" } else { $cur }
        })
    }

    $overall = Get-OverallStatus $checks
    # Data minimization: only these summary lines go to the AI, no user names, no computer name
    $summary = ($checks | ForEach-Object { "- [$($_.Status)] $($_.Category) / $($_.Check): $($_.Detail)" }) -join "`n"

    $system = @'
You are a friendly first-level IT support assistant at a small company.
You receive the results of automatic read-only checks from an employee's Windows laptop.
Answer in plain text without markdown symbols, in two parts.

FOR YOU:
Explain in 2 to 4 short sentences what the results mean, in simple words without jargon.
Then give at most 3 numbered steps the employee can safely try alone.
Never suggest turning off security features, installing software from the internet or editing the registry.

FOR IT SUPPORT:
One line starting with "Suspected cause:", then each red and yellow finding as a short technical line starting with "-".

If everything is green, say so and suggest contacting IT only if the problem continues.
Use only the results given. Never invent findings.
'@
    $system += "`nWrite the whole answer in $Language."

    Write-Host 'Asking the AI for an explanation...' -ForegroundColor Cyan
    $ai = Invoke-AiExplanation -SystemPrompt $system -UserContent "Check results:`n$summary" -NoAI:$NoAI

    $headline = @{
        Green  = 'Everything looks fine.'
        Yellow = 'Mostly fine, but some points need attention.'
        Red    = 'Problems found. See the red rows and the steps below.'
    }[$overall]

    New-HtmlReport -Title 'Laptop troubleshooting report' -Headline $headline -Overall $overall `
        -Checks $checks -AiText $ai -OutFile $OutFile
}