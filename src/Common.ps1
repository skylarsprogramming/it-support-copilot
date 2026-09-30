# Common.ps1 - shared helpers for IT Support Copilot

$script:Model = 'claude-haiku-4-5-20251001'   # small, fast, cheap model

# One check result = one row in the report
function New-Check {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Green','Yellow','Red')][string]$Status,
        [Parameter(Mandatory)][string]$Detail
    )
    [pscustomobject]@{ Category = $Category; Check = $Check; Status = $Status; Detail = $Detail }
}

# Worst status wins: one red check makes the whole report red
function Get-OverallStatus {
    param([object[]]$Checks)
    if ($Checks.Status -contains 'Red')    { return 'Red' }
    if ($Checks.Status -contains 'Yellow') { return 'Yellow' }
    return 'Green'
}

# Sends data to the AI and returns its text. Never throws: the tool still works without AI.
function Invoke-AiExplanation {
    param(
        [Parameter(Mandatory)][string]$SystemPrompt,
        [Parameter(Mandatory)][string]$UserContent,
        [switch]$NoAI
    )
    if ($NoAI) { return 'AI explanation switched off (-NoAI).' }
    $key = $env:ANTHROPIC_API_KEY
    if ([string]::IsNullOrWhiteSpace($key)) { return 'AI explanation skipped: ANTHROPIC_API_KEY is not set.' }

    $body = @{
        model      = $script:Model
        max_tokens = 900
        system     = $SystemPrompt
        messages   = @(@{ role = 'user'; content = $UserContent })
    } | ConvertTo-Json -Depth 6

    $headers = @{ 'x-api-key' = $key; 'anthropic-version' = '2023-06-01' }
    try {
        $r = Invoke-RestMethod -Uri 'https://api.anthropic.com/v1/messages' -Method Post `
            -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $body -TimeoutSec 60
        return (($r.content | Where-Object { $_.type -eq 'text' }).text -join "`n").Trim()
    }
    catch {
        return "AI explanation failed: $($_.Exception.Message)"
    }
}

# Escapes text so nothing from an email or a system can inject HTML into the report
function ConvertTo-SafeHtml {
    param([string]$Text)
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Headline,
        [Parameter(Mandatory)][ValidateSet('Green','Yellow','Red')][string]$Overall,
        [Parameter(Mandatory)][object[]]$Checks,
        [string]$AiText = '',
        [Parameter(Mandatory)][string]$OutFile
    )
    $rows = foreach ($c in $Checks) {
        $cls = $c.Status.ToLower()
        "<tr><td><span class='dot $cls'></span>$($c.Status)</td><td>$(ConvertTo-SafeHtml $c.Category)</td><td>$(ConvertTo-SafeHtml $c.Check)</td><td>$(ConvertTo-SafeHtml $c.Detail)</td></tr>"
    }
    $ai      = (ConvertTo-SafeHtml $AiText) -replace "`r?`n", '<br>'
    $created = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $cls     = $Overall.ToLower()

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>$(ConvertTo-SafeHtml $Title)</title>
<style>
 body { font-family: 'Segoe UI', Arial, sans-serif; margin: 32px auto; max-width: 960px; padding: 0 16px; color: #1f2328; }
 h1 { font-size: 24px; margin-bottom: 4px; }
 .meta { color: #656d76; margin-bottom: 24px; }
 .banner { padding: 16px 20px; border-radius: 8px; font-size: 18px; font-weight: 600; margin-bottom: 24px; }
 .banner.green { background: #dafbe1; } .banner.yellow { background: #fff8c5; } .banner.red { background: #ffebe9; }
 table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
 th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #d0d7de; vertical-align: top; }
 th { background: #f6f8fa; }
 .dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
 .dot.green { background: #1a7f37; } .dot.yellow { background: #bf8700; } .dot.red { background: #cf222e; }
 .ai { background: #f6f8fa; border-left: 4px solid #0969da; padding: 16px 20px; border-radius: 4px; line-height: 1.5; }
 .footer { color: #656d76; font-size: 12px; margin-top: 32px; }
</style></head><body>
<h1>$(ConvertTo-SafeHtml $Title)</h1>
<div class="meta">Created $created with IT Support Copilot</div>
<div class="banner $cls">$(ConvertTo-SafeHtml $Headline)</div>
<h2>Checks</h2>
<table><tr><th>Status</th><th>Area</th><th>Check</th><th>Result</th></tr>
$($rows -join "`n")
</table>
<h2>Explanation and next steps</h2>
<div class="ai">$ai</div>
<div class="footer">Checks and verdict are calculated locally by fixed rules. The AI text only explains them and cannot change them.</div>
</body></html>
"@

    $dir = Split-Path $OutFile -Parent
    if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $html | Out-File -FilePath $OutFile -Encoding utf8
    return $OutFile
}