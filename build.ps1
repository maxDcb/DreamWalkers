[CmdletBinding()]
param(
    [ValidateSet("x64", "x86", "arm64", "all")]
    [string]$Arch = "x64",

    [ValidateSet("all", "ci-smoke", "exe2h", "memoryModule", "memoryModuleAsm", "dotnetLoader", "goodClrDirectTest", "shellcodeTester", "testDll", "testExe", "smoke-payload")]
    [string]$Target = "all",

    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSCommandPath
$ArchList = if ($Arch -eq "all") { @("x64", "x86", "arm64") } else { @($Arch) }

function Resolve-CMake {
    $Command = Get-Command cmake -ErrorAction SilentlyContinue
    if ($null -ne $Command) {
        return $Command.Source
    }

    $Candidates = @(
        "$env:ProgramFiles\CMake\bin\cmake.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    )

    foreach ($Candidate in $Candidates) {
        if (Test-Path $Candidate) {
            return $Candidate
        }
    }

    throw "cmake.exe was not found. Install CMake or add it to PATH."
}

$CMake = Resolve-CMake

$Presets = @{
    x64 = "windows-x64"
    x86 = "windows-x86"
    arm64 = "windows-arm64"
}

$TargetMap = @{
    "all" = $null
    "ci-smoke" = "ci_smoke"
    "exe2h" = "exe2h"
    "memoryModule" = "loader"
    "memoryModuleAsm" = "memoryModuleAsm"
    "dotnetLoader" = "goodClr"
    "goodClrDirectTest" = "GoodClrDirectTest"
    "shellcodeTester" = "shellcodeTester"
    "testDll" = "implantDLL"
    "testExe" = "implant"
    "smoke-payload" = "smoke_payload"
}

$MemoryModuleHeaderTargets = @("all", "ci-smoke", "memoryModule")

function Build-HostExe2h {
    param(
        [string]$Config
    )

    $HostBuildDir = Join-Path $Root "build\x64"
    $HostExe2h = Join-Path $HostBuildDir "out\$Config\exe2h.exe"

    Push-Location $Root
    try {
        & $CMake --preset $Presets["x64"]
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configure failed for x64 host exe2h."
        }

        & $CMake --build $HostBuildDir --config $Config --target exe2h
        if ($LASTEXITCODE -ne 0) {
            throw "CMake build failed for x64 host exe2h."
        }
    }
    finally {
        Pop-Location
    }

    if (-not (Test-Path $HostExe2h)) {
        throw "x64 host exe2h was not produced at $HostExe2h."
    }
}

foreach ($CurrentArch in $ArchList) {
    $BuildDir = Join-Path $Root "build\$CurrentArch"

    if ($Clean -and (Test-Path $BuildDir)) {
        Remove-Item -Recurse -Force $BuildDir
    }

    Push-Location $Root
    try {
        $ConfigureArgs = @("--preset", $Presets[$CurrentArch])
        if ($CurrentArch -eq "arm64" -and $MemoryModuleHeaderTargets -contains $Target) {
            Build-HostExe2h -Config $Config
            $HostExe2h = Join-Path (Join-Path $Root "build\x64") "out\$Config\exe2h.exe"
            $HostExe2hForCMake = $HostExe2h -replace "\\", "/"
            $ConfigureArgs += "-DDW_EXE2H_HOST_PATH=$HostExe2hForCMake"
        }

        & $CMake @ConfigureArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configure failed for $CurrentArch."
        }

        $BuildArgs = @("--build", $BuildDir, "--config", $Config)
        if ($null -ne $TargetMap[$Target]) {
            $BuildArgs += @("--target", $TargetMap[$Target])
        }

        & $CMake @BuildArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CMake build failed for $CurrentArch."
        }
    }
    finally {
        Pop-Location
    }
}
