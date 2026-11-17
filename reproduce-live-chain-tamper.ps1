param(
    [string]$SourceUrl = "http://localhost:8081",
    [string]$CollectorUrl = "http://localhost:9091",
    [string]$OutputPath = "results\live-chain-tamper.csv"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $root $OutputPath
}

$web = New-Object System.Net.WebClient
$web.Encoding = [Text.Encoding]::UTF8
$rows = New-Object 'System.Collections.Generic.List[object]'

function Get-Json([string]$url) {
    return ($web.DownloadString($url) | ConvertFrom-Json)
}

function Post-Text([string]$url) {
    return $web.UploadString($url, "POST", "")
}

try {
    $overview = Get-Json "$SourceUrl/internal/overview"
    if (-not $overview.demoMode) {
        throw "The source demo mode is off; live experiment reset is unavailable."
    }

    Post-Text "$SourceUrl/internal/demo/reset" | Out-Null
    Post-Text "$SourceUrl/internal/simulate/typo" | Out-Null
    Post-Text "$SourceUrl/internal/demo/tamper" | Out-Null
    $tamperedForward = Post-Text "$SourceUrl/internal/forward"
    $tamperedStats = Get-Json "$CollectorUrl/api/stats"
    $tamperedAudit = @($tamperedStats.audit | Where-Object { $_.result -eq "CHAIN_BROKEN" })
    if ($tamperedForward -notmatch "^CHAIN_BROKEN" -or
        [int]$tamperedStats.records -ne 0 -or $tamperedAudit.Count -lt 1) {
        throw "Tamper was not rejected as expected: forward='$tamperedForward', records=$($tamperedStats.records)."
    }
    $rows.Add([pscustomobject]@{
        scenario = "mutated-pending-event"
        integrity_mode = "CHAIN"
        forward_response = $tamperedForward
        collector_records = [int]$tamperedStats.records
        audit_result = $tamperedAudit[0].result
        verification = (Get-Json "$CollectorUrl/api/verify").status
        outcome = "REJECTED"
    })

    Post-Text "$SourceUrl/internal/demo/reset" | Out-Null
    Post-Text "$SourceUrl/internal/simulate/typo" | Out-Null
    $validForward = Post-Text "$SourceUrl/internal/forward"
    $validStats = Get-Json "$CollectorUrl/api/stats"
    $validVerification = Get-Json "$CollectorUrl/api/verify"
    $sourceAfter = Get-Json "$SourceUrl/internal/overview"
    if ($validForward -notmatch "^OK \(seq 1-1\)$" -or
        [int]$validStats.records -ne 1 -or $validVerification.status -ne "OK" -or
        [int]$sourceAfter.stats.pending -ne 0) {
        throw "Valid recovery transfer failed: forward='$validForward', records=$($validStats.records), verify=$($validVerification.status)."
    }
    $rows.Add([pscustomobject]@{
        scenario = "clean-event-after-reset"
        integrity_mode = "CHAIN"
        forward_response = $validForward
        collector_records = [int]$validStats.records
        audit_result = "OK"
        verification = $validVerification.status
        outcome = "ACCEPTED"
    })

    $directory = [IO.Path]::GetDirectoryName($OutputPath)
    if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
    $rows | Format-Table -AutoSize
    Write-Output "Results: $OutputPath"
}
finally {
    $web.Dispose()
}
