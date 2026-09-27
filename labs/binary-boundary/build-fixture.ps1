param([string]$Clang = 'C:/Program Files/LLVM/bin/clang.exe')
$ErrorActionPreference = 'Stop'
$repoPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$fixtureOutput = Join-Path $repoPath 'dist/binary-boundary'
New-Item -ItemType Directory -Path $fixtureOutput -Force | Out-Null
foreach ($optimization in @('O0','O2')) {
    $outputFile = Join-Path $fixtureOutput "fixture-$optimization.dll"
    & $Clang --target=x86_64-pc-windows-msvc "-$optimization" -ffreestanding -fno-builtin -fno-stack-protector -shared -nostdlib -fuse-ld=lld '-Wl,/noentry' '-Wl,/timestamp:0' '-Wl,/Brepro' '-Wl,/nodefaultlib' (Join-Path $PSScriptRoot 'fixture.c') -o $outputFile
    if ($LASTEXITCODE -ne 0) { throw "Fixture build failed: $optimization" }
    Get-FileHash -LiteralPath $outputFile -Algorithm SHA256 | Select-Object Hash,Path
}
