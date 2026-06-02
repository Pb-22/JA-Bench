<#
Windows top-site browser PCAP collector for JA-Bench.

Purpose:
  Capture browser TCP/80 and TCP/443 traffic for a selected Tranco rank range while
  minimizing browser/OS background contamination with a resolved-target-IP BPF filter.
  Each launched browser process tree is terminated after its visit window, and matching
  target TCP connections are closed between visits unless -NoCloseTargetConnections is set.

Examples:
  powershell.exe -ExecutionPolicy Bypass -File C:\Tools\top-site-browser-pcap.ps1 -ListInterfaces
  powershell.exe -ExecutionPolicy Bypass -File C:\Tools\top-site-browser-pcap.ps1 -Browser Chrome  -StartRank 1 -Count 20 -Interface 1 -FreshRun
  powershell.exe -ExecutionPolicy Bypass -File C:\Tools\top-site-browser-pcap.ps1 -Browser Firefox -StartRank 1 -Count 20 -Interface 1 -FreshRun
  powershell.exe -ExecutionPolicy Bypass -File C:\Tools\top-site-browser-pcap.ps1 -Browser Edge    -StartRank 1 -Count 20 -Interface 1 -FreshRun
  powershell.exe -ExecutionPolicy Bypass -File C:\Tools\top-site-browser-pcap.ps1 -Browser All     -StartRank 1 -Count 20 -Interface 1 -FreshRun

Outputs one PCAPNG per browser plus sidecars:
  top-sites.csv, resolved-target-ips.csv, capture-filter.txt, visit-log.csv,
  pcap-files.csv, run-metadata.csv, *.dumpcap.log
#>

[CmdletBinding()]
param(
    [ValidateSet("Chrome", "Firefox", "Edge", "All")]
    [string]$Browser = "All",
    [int]$StartRank = 1,
    [int]$Count = 20,
    [string]$Interface = "1",
    [switch]$ListInterfaces,
    [string]$OutputDir = "$env:USERPROFILE\Desktop\TopSitesPcap",
    [switch]$FreshRun,
    [int]$PageSeconds = 12,
    [int]$BetweenSeconds = 2,
    [switch]$NoCloseTargetConnections,
    [double]$ConnectionSettleSeconds = 2.0,
    [string]$TrancoUrl = "https://tranco-list.eu/top-1m.csv.zip"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-Program {
    param([string[]]$Candidates)
    foreach ($p in $Candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return (Resolve-Path -LiteralPath $p).Path }
    }
    return $null
}

function ConvertTo-SafeFileToken {
    param([string]$Value)
    if (-not $Value) { return "unknown" }
    $token = $Value.Trim() -replace '[\\/:*?"<>|\s]+', '_'
    $token = $token -replace '[^A-Za-z0-9._-]', '_'
    $token = $token -replace '_+', '_'
    return $token.Trim('_.-')
}

function New-CleanDir {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Get-FullOsVersionToken {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        return ConvertTo-SafeFileToken ("{0}_{1}_build_{2}_{3}" -f $os.Caption, $os.Version, $os.BuildNumber, $os.OSArchitecture)
    } catch {
        return ConvertTo-SafeFileToken ([System.Environment]::OSVersion.VersionString)
    }
}

function Get-BrowserVersionToken {
    param([string]$BrowserName, [string]$ExePath)
    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath)
        $version = $info.ProductVersion
        if (-not $version) { $version = $info.FileVersion }
        if (-not $version) { $version = "unknown_version" }
        return ConvertTo-SafeFileToken ("{0}_{1}" -f $BrowserName, $version)
    } catch {
        return ConvertTo-SafeFileToken ("{0}_unknown_version" -f $BrowserName)
    }
}

function Resolve-SiteIps {
    param([string[]]$Domains)
    $rows = New-Object System.Collections.ArrayList
    $ips = New-Object System.Collections.Generic.HashSet[string]
    foreach ($domain in $Domains) {
        $names = New-Object System.Collections.ArrayList
        [void]$names.Add($domain)
        if ($domain -notlike "www.*") { [void]$names.Add("www.$domain") }
        foreach ($name in $names) {
            $nameAnswered = $false
            foreach ($recordType in @("A", "AAAA")) {
                try {
                    $answers = Resolve-DnsName -Name $name -Type $recordType -ErrorAction Stop |
                        Where-Object { $_.IPAddress } |
                        Select-Object -ExpandProperty IPAddress -Unique
                    foreach ($ip in $answers) {
                        $nameAnswered = $true
                        [void]$ips.Add([string]$ip)
                        [void]$rows.Add([pscustomobject]@{
                            site_domain = $domain
                            resolved_name = $name
                            record_type = $recordType
                            ip = [string]$ip
                        })
                    }
                } catch {}
            }
            if (-not $nameAnswered) {
                [void]$rows.Add([pscustomobject]@{
                    site_domain = $domain
                    resolved_name = $name
                    record_type = "A/AAAA"
                    ip = "RESOLUTION_FAILED"
                })
            }
        }
    }
    return [pscustomobject]@{ Rows = $rows; Ips = @($ips) }
}

function Build-CaptureFilter {
    param([string[]]$Ips)
    if (-not $Ips -or $Ips.Count -eq 0) { throw "No target IPs resolved; refusing to capture broad traffic." }
    $hostTerms = $Ips | Sort-Object | ForEach-Object { "host $_" }
    return "tcp and (port 80 or port 443) and (" + ($hostTerms -join " or ") + ")"
}

function Start-FilteredCapture {
    param([string]$DumpcapPath, [string]$Interface, [string]$Filter, [string]$PcapPath, [string]$LogPath)
    # PowerShell 5 can split a multi-word BPF filter if passed as string[].
    # Pass a single command-line string so dumpcap receives one -f argument.
    $dumpcapArgs = '-i "{0}" -f "{1}" -w "{2}"' -f $Interface, $Filter, $PcapPath
    $cap = Start-Process -FilePath $DumpcapPath -ArgumentList $dumpcapArgs -RedirectStandardError $LogPath -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 4
    if ($cap.HasExited) {
        $err = ""
        if (Test-Path -LiteralPath $LogPath) { $err = Get-Content -LiteralPath $LogPath -Raw }
        if ($err) { throw "dumpcap exited early:`n$err" }
        throw "dumpcap exited early; stderr log was empty: $LogPath"
    }
    return $cap
}

function Stop-FilteredCapture {
    param([System.Diagnostics.Process]$CaptureProcess)
    if (-not $CaptureProcess) { return }
    try { $CaptureProcess.Refresh() } catch { return }
    if (-not $CaptureProcess.HasExited) { Stop-Process -Id $CaptureProcess.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}

function Stop-ProcessTree {
    param([System.Diagnostics.Process]$Proc)
    if (-not $Proc) { return }
    try { $Proc.Refresh() } catch { return }
    if ($Proc.HasExited) { return }
    try { & "$env:WINDIR\System32\taskkill.exe" /PID $Proc.Id /T /F | Out-Null }
    catch { Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue }
}

function Close-TargetBrowserConnections {
    param(
        [string[]]$TargetIps,
        [string]$BrowserName,
        [double]$SettleSeconds = 2.0
    )
    if (-not $TargetIps -or $TargetIps.Count -eq 0) {
        Start-Sleep -Seconds $SettleSeconds
        return
    }
    $allowedNames = switch ($BrowserName) {
        "Chrome" { @("chrome") }
        "Edge" { @("msedge") }
        "Firefox" { @("firefox") }
        default { @() }
    }
    if ($allowedNames.Count -eq 0) {
        Start-Sleep -Seconds $SettleSeconds
        return
    }
    try {
        $targetSet = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]$TargetIps)
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.RemotePort -in @(80, 443) -and $targetSet.Contains([string]$_.RemoteAddress) }
        foreach ($conn in $connections) {
            if (-not $conn.OwningProcess) { continue }
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
                if ($allowedNames -contains $proc.ProcessName) {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    } catch {}
    Start-Sleep -Seconds $SettleSeconds
}

function Write-FirefoxProfilePrefs {
    param([string]$ProfileDir)
    New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
    @'
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.startup.page", 0);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.newtabpage.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("network.http.http3.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("extensions.update.enabled", false);
user_pref("app.update.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
'@ | Set-Content -LiteralPath (Join-Path $ProfileDir "user.js") -Encoding ASCII
}

function Visit-Url-WithBrowser {
    param([string]$BrowserName, [string]$ExePath, [string]$Url, [string]$ProfileRoot, [int]$Seconds)
    $safeUrl = $Url -replace '[^A-Za-z0-9_.-]', '_'
    $profileDir = Join-Path $ProfileRoot $safeUrl
    New-CleanDir -Path $profileDir

    if ($BrowserName -eq "Firefox") { Write-FirefoxProfilePrefs -ProfileDir $profileDir }

    switch ($BrowserName) {
        "Chrome" {
            $args = @(
                "--user-data-dir=$profileDir", "--new-window", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-sync", "--disable-extensions", "--disable-component-update",
                "--disable-default-apps", "--disable-quic", "--disable-features=UseDnsHttpsSvcbAlpn,EncryptedClientHello",
                $Url
            )
        }
        "Edge" {
            $args = @(
                "--user-data-dir=$profileDir", "--new-window", "--no-first-run", "--no-default-browser-check",
                "--disable-background-networking", "--disable-sync", "--disable-extensions", "--disable-component-update",
                "--disable-default-apps", "--disable-quic", "--disable-features=UseDnsHttpsSvcbAlpn,EncryptedClientHello",
                $Url
            )
        }
        "Firefox" { $args = @("-no-remote", "-profile", $profileDir, "-new-window", $Url) }
        default { throw "Unknown browser: $BrowserName" }
    }

    $p = Start-Process -FilePath $ExePath -ArgumentList $args -PassThru
    Start-Sleep -Seconds $Seconds
    Stop-ProcessTree -Proc $p
    Start-Sleep -Seconds $BetweenSeconds
}

if ($StartRank -lt 1) { throw "-StartRank must be 1 or greater." }
if ($Count -lt 1) { throw "-Count must be 1 or greater." }
$EndRank = $StartRank + $Count - 1
$RangeToken = "{0}-{1}" -f $StartRank, $EndRank

$dumpcap = Find-Program @("$env:ProgramFiles\Wireshark\dumpcap.exe", "${env:ProgramFiles(x86)}\Wireshark\dumpcap.exe")
if (-not $dumpcap) { throw "Could not find dumpcap.exe. Install Wireshark/Npcap first." }
if ($ListInterfaces) { & $dumpcap -D; exit 0 }

$browserDefs = @()
if ($Browser -eq "All" -or $Browser -eq "Chrome") {
    $path = Find-Program @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
    if (-not $path) { throw "Chrome selected but chrome.exe was not found." }
    $browserDefs += [pscustomobject]@{ Name = "Chrome"; Path = $path }
}
if ($Browser -eq "All" -or $Browser -eq "Firefox") {
    $path = Find-Program @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
    if (-not $path) { throw "Firefox selected but firefox.exe was not found." }
    $browserDefs += [pscustomobject]@{ Name = "Firefox"; Path = $path }
}
if ($Browser -eq "All" -or $Browser -eq "Edge") {
    $path = Find-Program @("$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    if (-not $path) { throw "Edge selected but msedge.exe was not found." }
    $browserDefs += [pscustomobject]@{ Name = "Edge"; Path = $path }
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutputDir ("top-sites-{0}-{1}" -f $RangeToken, $stamp)
if ((Test-Path -LiteralPath $runDir) -and $FreshRun) { Remove-Item -LiteralPath $runDir -Recurse -Force }
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$tmp = Join-Path $runDir "tmp"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

Write-Host "Downloading Tranco list..."
$zipPath = Join-Path $tmp "top-1m.csv.zip"
Invoke-WebRequest -Uri $TrancoUrl -OutFile $zipPath -UseBasicParsing
Expand-Archive -LiteralPath $zipPath -DestinationPath $tmp -Force
$csvPath = Join-Path $tmp "top-1m.csv"
if (-not (Test-Path -LiteralPath $csvPath)) { throw "Expected $csvPath after extracting Tranco ZIP." }

$sites = @(Get-Content -LiteralPath $csvPath -TotalCount $EndRank | Select-Object -Skip ($StartRank - 1) | ForEach-Object { ($_ -split ',', 2)[1].Trim().ToLowerInvariant() })
if ($sites.Count -ne $Count) { throw "Expected $Count sites for ranks $RangeToken, got $($sites.Count)." }

$topSitesPath = Join-Path $runDir "top-sites.csv"
$rank = $StartRank - 1
$sites | ForEach-Object {
    $rank++
    [pscustomobject]@{ rank = $rank; domain = $_ }
} | Export-Csv -LiteralPath $topSitesPath -NoTypeInformation

Write-Host "Resolving rank $RangeToken target IPs..."
$resolution = Resolve-SiteIps -Domains $sites
$resolvedIpsPath = Join-Path $runDir "resolved-target-ips.csv"
$resolution.Rows | Export-Csv -LiteralPath $resolvedIpsPath -NoTypeInformation
$filter = Build-CaptureFilter -Ips $resolution.Ips
$filterPath = Join-Path $runDir "capture-filter.txt"
$filter | Set-Content -LiteralPath $filterPath -Encoding ASCII

$osToken = Get-FullOsVersionToken
$profilesRoot = Join-Path $runDir "browser-profiles"
New-Item -ItemType Directory -Path $profilesRoot -Force | Out-Null
$visitLog = Join-Path $runDir "visit-log.csv"
$pcapManifest = Join-Path $runDir "pcap-files.csv"
$metadataPath = Join-Path $runDir "run-metadata.csv"

$browserDefs | ForEach-Object {
    [pscustomobject]@{
        os_version_token = $osToken
        browser = $_.Name
        browser_path = $_.Path
        browser_version_token = Get-BrowserVersionToken -BrowserName $_.Name -ExePath $_.Path
        site_range = $RangeToken
        capture_filter = $filter
    }
} | Export-Csv -LiteralPath $metadataPath -NoTypeInformation

$visitRows = New-Object System.Collections.ArrayList
$pcapRows = New-Object System.Collections.ArrayList

Write-Host "Output directory: $runDir"
Write-Host "Capture filter: $filterPath"
Write-Host "Browsers: $($browserDefs.Name -join ', ')"

foreach ($b in $browserDefs) {
    $versionToken = Get-BrowserVersionToken -BrowserName $b.Name -ExePath $b.Path
    $fileBase = "{0}_{1}_{2}" -f $osToken, $versionToken, $RangeToken
    $pcapPath = Join-Path $runDir "$fileBase.pcapng"
    $dumpcapLog = Join-Path $runDir "$fileBase.dumpcap.log"
    $profileRoot = Join-Path $profilesRoot $b.Name
    New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null

    Write-Host "Starting capture for $($b.Name) on interface $Interface"
    $cap = $null
    try {
        $cap = Start-FilteredCapture -DumpcapPath $dumpcap -Interface $Interface -Filter $filter -PcapPath $pcapPath -LogPath $dumpcapLog
        [void]$pcapRows.Add([pscustomobject]@{ browser = $b.Name; pcap_path = $pcapPath; dumpcap_log = $dumpcapLog; browser_version_token = $versionToken; site_range = $RangeToken })
        $pcapRows | Export-Csv -LiteralPath $pcapManifest -NoTypeInformation

        $rank = $StartRank - 1
        foreach ($site in $sites) {
            $rank++
            foreach ($scheme in @("http", "https")) {
                $url = "${scheme}://$site/"
                $started = Get-Date
                Write-Host ("{0} rank {1}: {2}" -f $b.Name, $rank, $url)
                Visit-Url-WithBrowser -BrowserName $b.Name -ExePath $b.Path -Url $url -ProfileRoot $profileRoot -Seconds $PageSeconds
                if (-not $NoCloseTargetConnections) {
                    Close-TargetBrowserConnections -TargetIps $resolution.Ips -BrowserName $b.Name -SettleSeconds $ConnectionSettleSeconds
                }
                $ended = Get-Date
                [void]$visitRows.Add([pscustomobject]@{
                    browser = $b.Name; rank = $rank; domain = $site; scheme = $scheme; url = $url;
                    pcap_path = $pcapPath; start_utc = $started.ToUniversalTime().ToString("o"); end_utc = $ended.ToUniversalTime().ToString("o")
                })
                $visitRows | Export-Csv -LiteralPath $visitLog -NoTypeInformation
            }
        }
    } finally {
        Write-Host "Stopping capture for $($b.Name)..."
        Stop-FilteredCapture -CaptureProcess $cap
    }
}

Write-Host "Done. Output directory: $runDir"
Write-Host "PCAP manifest: $pcapManifest"
Write-Host "Visit log: $visitLog"
Write-Host "Resolved IPs: $resolvedIpsPath"
Write-Host "Capture filter: $filterPath"
