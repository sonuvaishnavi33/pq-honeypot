$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$results = Join-Path $root "results"
New-Item -ItemType Directory -Force -Path $results | Out-Null

$jdkCandidate = Join-Path $env:USERPROFILE ".jdk\jdk-25"
if (Test-Path (Join-Path $jdkCandidate "bin\java.exe")) {
    $env:JAVA_HOME = $jdkCandidate
}
if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    throw "Set JAVA_HOME to a Java 25 installation before capturing the environment."
}
$env:PATH = (Join-Path $env:JAVA_HOME "bin") + ";" + $env:PATH
$javaOutput = & $env:ComSpec /c "`"$env:JAVA_HOME\bin\java.exe`" -version 2>&1"
$javaVersion = ($javaOutput | Select-Object -First 1).ToString()
if ($javaVersion -notmatch 'version "25\.') {
    throw "Environment capture requires Java 25; found $javaVersion"
}
$mavenCandidate = Join-Path $env:USERPROFILE "maven\bin"
if (-not (Get-Command mvn -ErrorAction SilentlyContinue) -and
    (Test-Path (Join-Path $mavenCandidate "mvn.cmd"))) {
    $env:PATH = $mavenCandidate + ";" + $env:PATH
}

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$mavenOutput = & $env:ComSpec /c "mvn -version 2>&1"
$mavenVersion = ($mavenOutput | Where-Object { $_ -match "^Apache Maven " } |
    Select-Object -First 1).ToString()
$manifest = [ordered]@{
    capturedAtUtc = [DateTime]::UtcNow.ToString("o")
    operatingSystem = $os.Caption
    osVersion = $os.Version
    java = $javaVersion
    maven = $mavenVersion
    processor = $cpu.Name
    logicalProcessors = [int]$cpu.NumberOfLogicalProcessors
    memoryGiB = [Math]::Round([double]$os.TotalVisibleMemorySize / 1MB, 2)
    project = [ordered]@{
        javaTarget = 25
        springBoot = "3.5.16"
        database = "MySQL 8.4"
    }
    researchConfig = [ordered]@{
        seed = 42
        attackMatrixTrials = 200
        exposureTrialsPerSetting = 2000
        kemRuns = 30
        kemIterationsPerRun = 200
        kemWarmup = 300
    }
    secretValuesIncluded = $false
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $results "environment.json")
Write-Output "Wrote results\environment.json (no credentials or environment secret values included)."
