param(
    [string]$SourceUrl = "http://localhost:8081",
    [string]$CollectorUrl = "http://localhost:9091",
    [ValidateSet("NONE", "CHAIN", "CHAIN_ANCHOR", "CHAIN_RATCHET", "FULL")]
    [string]$Mode = "FULL",
    [ValidateSet("X25519", "ML_KEM_768", "HYBRID")]
    [string]$KemMode = "ML_KEM_768",
    [ValidateRange(1, 10000)]
    [int]$Trials = 30,
    [string]$OutputPath = "results\live-service-$Mode-$KemMode.csv"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $root $OutputPath
}
$summaryPath = [IO.Path]::Combine(
    [IO.Path]::GetDirectoryName($OutputPath),
    ([IO.Path]::GetFileNameWithoutExtension($OutputPath) + "-summary.csv"))
$client = New-Object System.Net.WebClient
$client.Encoding = [Text.Encoding]::UTF8
$measurements = New-Object 'System.Collections.Generic.List[object]'

function Get-Json($path) {
    return ($client.DownloadString($path) | ConvertFrom-Json)
}

function Post-Text($path) {
    return $client.UploadString($path, "POST", "")
}

try {
    $sourceOverview = Get-Json "$SourceUrl/internal/overview"
    $collectorStats = Get-Json "$CollectorUrl/api/stats"
    if (-not $sourceOverview.demoMode) {
        throw "The source demo mode is off; live benchmark reset is unavailable."
    }

    for ($trial = 1; $trial -le $Trials; $trial++) {
        Post-Text "$SourceUrl/internal/demo/reset" | Out-Null
        1..5 | ForEach-Object { Post-Text "$SourceUrl/internal/simulate/typo" | Out-Null }

        $timer = [Diagnostics.Stopwatch]::StartNew()
        $forward = Post-Text "$SourceUrl/internal/forward"
        $timer.Stop()

        $collectorStats = Get-Json "$CollectorUrl/api/stats"
        $verification = Get-Json "$CollectorUrl/api/verify"
        $sourceOverview = Get-Json "$SourceUrl/internal/overview"
        if ($forward -notmatch '^OK \(seq 1-5\)$' -or
            [int]$collectorStats.records -ne 5 -or
            $verification.status -ne "OK" -or
            [int]$sourceOverview.stats.pending -ne 0) {
            throw "Trial $trial failed: forward='$forward', records=$($collectorStats.records), verify=$($verification.status), pending=$($sourceOverview.stats.pending)"
        }

        $measurements.Add([pscustomobject]@{
            mode = $Mode
            kem_mode = $KemMode
            trial = $trial
            forward_ms = [Math]::Round($timer.Elapsed.TotalMilliseconds, 3)
            accepted_records = [int]$collectorStats.records
            verification = $verification.status
        })
    }

    $directory = [IO.Path]::GetDirectoryName($OutputPath)
    if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    $measurements | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath

    $values = @($measurements | ForEach-Object { [double]$_.forward_ms })
    $sorted = @($values | Sort-Object)
    $random = New-Object System.Random(42)
    $bootstrap = New-Object 'System.Collections.Generic.List[double]'
    for ($sample = 0; $sample -lt 5000; $sample++) {
        $sum = 0.0
        for ($i = 0; $i -lt $values.Count; $i++) {
            $sum += $values[$random.Next(0, $values.Count)]
        }
        $bootstrap.Add($sum / $values.Count)
    }
    $bootstrapSorted = @($bootstrap | Sort-Object)
    $lowIndex = [int][Math]::Floor(0.025 * ($bootstrapSorted.Count - 1))
    $highIndex = [int][Math]::Ceiling(0.975 * ($bootstrapSorted.Count - 1))
    $p95Index = [int][Math]::Ceiling(0.95 * $sorted.Count) - 1
    $summary = [pscustomobject]@{
        mode = $Mode
        kem_mode = $KemMode
        trials = $Trials
        all_accepted = $true
        mean_ms = [Math]::Round(($values | Measure-Object -Average).Average, 3)
        mean_ci95_low_ms = [Math]::Round($bootstrapSorted[$lowIndex], 3)
        mean_ci95_high_ms = [Math]::Round($bootstrapSorted[$highIndex], 3)
        median_ms = [Math]::Round($sorted[[int][Math]::Floor(($sorted.Count - 1) / 2)], 3)
        p95_ms = [Math]::Round($sorted[$p95Index], 3)
        min_ms = [Math]::Round($sorted[0], 3)
        max_ms = [Math]::Round($sorted[$sorted.Count - 1], 3)
    }
    $summary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryPath
    $summary | Format-List
    Write-Output "Raw trials: $OutputPath"
    Write-Output "Summary: $summaryPath"
}
finally {
    $client.Dispose()
}
