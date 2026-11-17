$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $jdkCandidate = Join-Path $env:USERPROFILE ".jdk\jdk-25"
    if (Test-Path (Join-Path $jdkCandidate "bin\java.exe")) {
        $env:JAVA_HOME = $jdkCandidate
    }
    if (-not $env:JAVA_HOME -or -not (Test-Path (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
        throw "Set JAVA_HOME to a Java 25 installation before reproducing the experiments."
    }
    $env:PATH = (Join-Path $env:JAVA_HOME "bin") + ";" + $env:PATH
    $javaOutput = & $env:ComSpec /c "`"$env:JAVA_HOME\bin\java.exe`" -version 2>&1"
    $javaVersion = ($javaOutput | Select-Object -First 1).ToString()
    if ($javaVersion -notmatch 'version "25\.') {
        throw "Experiment reproduction requires Java 25; found $javaVersion"
    }
    $mavenCandidate = Join-Path $env:USERPROFILE "maven\bin"
    if (-not (Get-Command mvn -ErrorAction SilentlyContinue) -and
        (Test-Path (Join-Path $mavenCandidate "mvn.cmd"))) {
        $env:PATH = $mavenCandidate + ";" + $env:PATH
    }

    & mvn test
    if ($LASTEXITCODE -ne 0) { throw "Maven tests failed with exit code $LASTEXITCODE" }

    & mvn -q dependency:build-classpath "-Dmdep.outputFile=target\research-classpath.txt"
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve the research runtime classpath" }
    $runtimeClasspath = "target\classes;" + (Get-Content "target\research-classpath.txt" -Raw)

    $selfCheckOutput = & java -cp $runtimeClasspath pqh.research.ResearchSelfCheck
    $selfCheckExit = $LASTEXITCODE
    $selfCheckOutput | Set-Content -Encoding UTF8 "results\research-selfcheck.txt"
    $selfCheckOutput
    if ($selfCheckExit -ne 0) { throw "Research self-check failed with exit code $selfCheckExit" }
    & java -cp $runtimeClasspath pqh.research.AttackMatrixMain
    if ($LASTEXITCODE -ne 0) { throw "Reference attack matrix failed with exit code $LASTEXITCODE" }
    & java -cp $runtimeClasspath pqh.research.ExposureExperiment
    if ($LASTEXITCODE -ne 0) { throw "Exposure model failed with exit code $LASTEXITCODE" }
    & java -cp $runtimeClasspath pqh.research.KemBenchmark
    if ($LASTEXITCODE -ne 0) { throw "Cryptographic microbenchmark failed with exit code $LASTEXITCODE" }

    & python generate-research-tables.py
    if ($LASTEXITCODE -ne 0) { throw "Research table generation failed with exit code $LASTEXITCODE" }
    & python generate-research-figures.py
    if ($LASTEXITCODE -ne 0) { throw "Research figure generation failed with exit code $LASTEXITCODE" }
    & .\Capture-ResearchEnvironment.ps1
    if ($LASTEXITCODE -ne 0) { throw "Environment capture failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
