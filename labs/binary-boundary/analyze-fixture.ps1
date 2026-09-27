param([string]$GhidraHome = (Join-Path $env:LOCALAPPDATA 'CodexResearchTools/ghidra_12.1.3_PUBLIC'))
$ErrorActionPreference = 'Stop'
$repoPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixturePath = Join-Path $repoPath 'dist/binary-boundary'
$projectPath = Join-Path $fixturePath 'ghidra-projects'
New-Item -ItemType Directory -Path $projectPath -Force | Out-Null
$launcher = Join-Path $GhidraHome 'support/analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $launcher)) { throw 'Set -GhidraHome to an extracted official release.' }
$previousJdkOptions = $env:JDK_JAVA_OPTIONS
$cachePath = Join-Path $fixturePath 'cache'
$settingsPath = Join-Path $fixturePath 'settings'
$tempPath = Join-Path $fixturePath 'temp'
foreach ($directory in @($cachePath,$settingsPath,$tempPath)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
# Explicit local directories avoid Windows app-container path redirection in OSGi.
$env:JDK_JAVA_OPTIONS = "$previousJdkOptions `"-Dapplication.cachedir=$cachePath`" `"-Dapplication.settingsdir=$settingsPath`" `"-Dapplication.tempdir=$tempPath`""
try { foreach ($optimization in @('O0','O2')) {
    $inputDll = Join-Path $fixturePath "fixture-$optimization.dll"
    $outputJson = Join-Path $PSScriptRoot "analysis-$optimization.json"
    if (-not (Test-Path -LiteralPath $inputDll)) { throw 'Build the controlled fixtures first.' }
    # A new project name preserves previous runs without overwriting analysis.
    $projectName = "boundary-$optimization-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
    $freshReport = Join-Path $fixturePath "$projectName.json"
    & $launcher $projectPath $projectName -import $inputDll -scriptPath $PSScriptRoot -postScript ExportBoundary.java $freshReport -analysisTimeoutPerFile 120 -max-cpu 2
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $freshReport)) { throw "Ghidra analysis failed: $optimization" }
    $report = Get-Content -Raw -LiteralPath $freshReport | ConvertFrom-Json
    $inputHash = (Get-FileHash -LiteralPath $inputDll -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($report.functions.Count -ne 4 -or $report.binary_sha256 -ne $inputHash) { throw 'Analysis output does not match the input fixture.' }
    Copy-Item -LiteralPath $freshReport -Destination $outputJson
} } finally { $env:JDK_JAVA_OPTIONS = $previousJdkOptions }
