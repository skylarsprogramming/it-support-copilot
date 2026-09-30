<#
.SYNOPSIS
  IT Support Copilot: AI-assisted Windows troubleshooting and phishing email analysis.
.EXAMPLE
  .\src\Start-Copilot.ps1
.EXAMPLE
  .\src\Start-Copilot.ps1 -Mode Troubleshoot -Language German
.EXAMPLE
  .\src\Start-Copilot.ps1 -Mode Phishing -EmailFile .\samples\emails\phishing-microsoft.eml
.EXAMPLE
  .\src\Start-Copilot.ps1 -Mode Troubleshoot -ScenarioFile .\samples\scenarios\dns-broken.json
#>
[CmdletBinding()]
param(
    [ValidateSet('Troubleshoot','Phishing')][string]$Mode,
    [string]$EmailFile,
    [string]$ScenarioFile,
    [ValidateSet('English','German')][string]$Language = 'English',
    [switch]$NoAI,
    [switch]$NoOpen
)

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host 'Please run this tool in PowerShell 7 (pwsh).' -ForegroundColor Red
    exit 1
}

. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Diagnostics.ps1')
. (Join-Path $PSScriptRoot 'Phishing.ps1')

Write-Host ''
Write-Host '  IT Support Copilot' -ForegroundColor Green
Write-Host '  Local checks decide. The AI only explains.' -ForegroundColor DarkGray
Write-Host ''

if (-not $Mode) {
    Write-Host '  [1] My laptop or internet has a problem'
    Write-Host '  [2] Check a suspicious email (.eml file)'
    $choice = Read-Host '  Choose 1 or 2'
    $Mode = if ($choice -eq '2') { 'Phishing' } else { 'Troubleshoot' }
}

if ($Mode -eq 'Phishing' -and -not $EmailFile) {
    $EmailFile = (Read-Host '  Path to the .eml file (you can drag the file into this window)').Trim('"', ' ')
}

try {
    $report = if ($Mode -eq 'Phishing') {
        Invoke-PhishingCheck -EmailFile $EmailFile -Language $Language -NoAI:$NoAI
    } else {
        Invoke-Diagnostics -ScenarioFile $ScenarioFile -Language $Language -NoAI:$NoAI
    }
    Write-Host "  Report saved: $report" -ForegroundColor Green
    if (-not $NoOpen) { Start-Process $report }
}
catch {
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}