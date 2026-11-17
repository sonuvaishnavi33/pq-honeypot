param(
    [string]$SourceUrl = "http://localhost:8081",
    [string]$CollectorUrl = "http://localhost:9091",
    [string]$RawOutputPath = "results\live-detection-rules.csv",
    [string]$SummaryOutputPath = "results\live-detection-rules-summary.csv"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not [IO.Path]::IsPathRooted($RawOutputPath)) {
    $RawOutputPath = Join-Path $root $RawOutputPath
}
if (-not [IO.Path]::IsPathRooted($SummaryOutputPath)) {
    $SummaryOutputPath = Join-Path $root $SummaryOutputPath
}

Add-Type -AssemblyName System.Net.Http
$http = New-Object System.Net.Http.HttpClient
$web = New-Object System.Net.WebClient
$web.Encoding = [Text.Encoding]::UTF8
$cases = @(
    [pscustomobject]@{ id = "encoded-union-marker"; category = "positive"; query = "probe=union select local_test" },
    [pscustomobject]@{ id = "encoded-script-marker"; category = "positive"; query = "probe=<script>" },
    [pscustomobject]@{ id = "encoded-traversal-marker"; category = "positive"; query = "probe=../etc/passwd" },
    [pscustomobject]@{ id = "encoded-tautology-marker"; category = "positive"; query = "probe=' OR '1'='1" },
    [pscustomobject]@{ id = "triple-encoded-script-marker"; category = "positive"; query = "probe=%253Cscript%253E" },
    [pscustomobject]@{ id = "benign-weather"; category = "benign"; query = "city=summer weather" },
    [pscustomobject]@{ id = "benign-select-text"; category = "benign"; query = "q=select something" },
    [pscustomobject]@{ id = "benign-profile-path"; category = "benign"; query = "redirect=/home/profile" },
    [pscustomobject]@{ id = "benign-percent"; category = "benign"; query = "value=100%" },
    [pscustomobject]@{ id = "benign-message"; category = "benign"; query = "message=one two" }
)

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
    foreach ($case in $cases) {
        $encodedQuery = [Uri]::EscapeDataString($case.query)
        $request = New-Object System.Net.Http.HttpRequestMessage(
            [System.Net.Http.HttpMethod]::Get,
            "$SourceUrl/admin?$encodedQuery"
        )
        $response = $http.SendAsync($request).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        $response.Dispose()
        $request.Dispose()
        if ($status -ne 403) {
            throw "Case '$($case.id)' returned HTTP $status; expected the decoy endpoint's 403."
        }
    }

    $overview = Get-Json "$SourceUrl/internal/overview"
    $events = @($overview.events | Sort-Object { [int]$_.seq_no })
    if ($events.Count -ne $cases.Count) {
        throw "Expected $($cases.Count) recorded requests, found $($events.Count)."
    }

    $results = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $cases.Count; $index++) {
        $case = $cases[$index]
        $event = $events[$index]
        $rules = [string]$event.rules_hit
        $ruleTokens = @($rules -split ',')
        $detected = $ruleTokens -contains "R6"
        $decodedDetection = $ruleTokens -contains "R6D"
        $expected = $case.category -eq "positive"
        $passed = $expected -eq $detected
        if ($expected) { $passed = $passed -and $decodedDetection }
        $results.Add([pscustomobject]@{
            case_id = $case.id
            category = $case.category
            sequence = [int]$event.seq_no
            expected_detection = $expected
            detected = $detected
            decoded_detection = $decodedDetection
            rules_hit = $rules
            result = if ($passed) { "PASS" } else { "FAIL" }
        })
    }

    $positive = @($results | Where-Object { $_.category -eq "positive" })
    $benign = @($results | Where-Object { $_.category -eq "benign" })
    $truePositive = @($positive | Where-Object { $_.detected }).Count
    $falseNegative = $positive.Count - $truePositive
    $falsePositive = @($benign | Where-Object { $_.detected }).Count
    $trueNegative = $benign.Count - $falsePositive
    $accuracy = ($truePositive + $trueNegative) / ($positive.Count + $benign.Count)
    $recall = if ($positive.Count) { $truePositive / $positive.Count } else { 0 }
    $specificity = if ($benign.Count) { $trueNegative / $benign.Count } else { 0 }
    $precisionDenominator = $truePositive + $falsePositive
    $precision = if ($precisionDenominator) { $truePositive / $precisionDenominator } else { 0 }

    $forwards = @(
        (Post-Text "$SourceUrl/internal/forward"),
        (Post-Text "$SourceUrl/internal/forward")
    )
    $stats = Get-Json "$CollectorUrl/api/stats"
    $verification = Get-Json "$CollectorUrl/api/verify"
    if ([int]$stats.records -ne $cases.Count -or $verification.status -ne "OK") {
        throw "Evidence transfer/verification failed: records=$($stats.records), status=$($verification.status)."
    }
    if (@($results | Where-Object { $_.result -ne "PASS" }).Count -gt 0) {
        throw "At least one live detection case did not match its expected label."
    }

    $rawDirectory = [IO.Path]::GetDirectoryName($RawOutputPath)
    if ($rawDirectory) { [IO.Directory]::CreateDirectory($rawDirectory) | Out-Null }
    $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $RawOutputPath
    $summary = [pscustomobject]@{
        positive_cases = $positive.Count
        benign_cases = $benign.Count
        true_positive = $truePositive
        false_negative = $falseNegative
        false_positive = $falsePositive
        true_negative = $trueNegative
        accuracy = [Math]::Round($accuracy, 4)
        precision = [Math]::Round($precision, 4)
        recall = [Math]::Round($recall, 4)
        specificity = [Math]::Round($specificity, 4)
        all_evidence_accepted = ([int]$stats.records -eq $cases.Count)
        collector_verification = $verification.status
        forward_responses = ($forwards -join "; ")
    }
    $summaryDirectory = [IO.Path]::GetDirectoryName($SummaryOutputPath)
    if ($summaryDirectory) { [IO.Directory]::CreateDirectory($summaryDirectory) | Out-Null }
    $summary | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $SummaryOutputPath
    $summary | Format-List
    Write-Output "Raw cases: $RawOutputPath"
    Write-Output "Summary: $SummaryOutputPath"
}
finally {
    $http.Dispose()
    $web.Dispose()
}
