# php extension installer

param (
    [string]$ExtName,
    [string]$PhpBin= "php",
    [string]$ExtPath = ".",
    [bool]$Enable = $false
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "install" -MaxTry $MaxTry

info "Start installing php extension"
$origwd = (Get-Location).Path
Set-Location $ExtPath

$phppath = ((Get-Command $PhpBin).Source | Select-String -Pattern '(.+)\\php\.exe').Matches.Groups[1].Value
$extdir = & $PhpBin -r "echo ini_get('extension_dir');"
$extdir_ini = ""
if (![System.IO.Path]::IsPathRooted($extdir)){
    # if it's not absolute, it's relative path to $phppath
    # we need set full path in ini
    $extdir = "$phppath\$extdir"
    $extdir_ini = "extension_dir=$extdir"
}
$inipath = "$phppath\php.ini"

if(-Not (Test-Path "$env:BUILD_DIR\php_$ExtName.dll" -PathType Leaf)){
    err "Could not found $env:BUILD_DIR\php_$ExtName.dll, do we running in env.bat?"
    Set-Location $origwd
    exit 1
}

if(-Not (Test-Path $extdir -PathType Container)){
    info "Create extension dir $extdir"
    New-Item -Path $extdir -ItemType Container | Out-Null
}

info "Copy $env:BUILD_DIR\php_$ExtName.dll to $extdir"
Copy-Item "$env:BUILD_DIR\php_$ExtName.dll" $extdir | Out-Null

# Resolve and copy dependency DLLs to PHP directory.
# When PHP loads php_swoole.dll, Windows must find all imported DLLs.
# They are in the deps directory (PHP_BUILD) but not on the runtime PATH.
info "Resolving DLL dependencies for php_$ExtName.dll"

$depsRoot = $env:PHP_BUILD
if (-not $depsRoot) { $depsRoot = "$env:TOOLS_PATH\deps" }

$systemDllPatterns = @(
    "KERNEL32.dll", "ADVAPI32.dll", "SHELL32.dll", "ole32.dll", "OLEAUT32.dll",
    "USER32.dll", "GDI32.dll", "WS2_32.dll", "IPHLPAPI.DLL", "CRYPT32.dll",
    "VCRUNTIME*.dll", "MSVCP*.dll", "CONCRT*.dll", "VCOMP*.dll",
    "api-ms-win-*", "ext-ms-win-*", "ntdll.dll", "bcrypt.dll", "Secur32.dll",
    "VERSION.dll", "WINMM.dll", "WLDAP32.dll", "NORMALIZ.dll", "NETAPI32.dll",
    "ucrtbase.dll", "bcryptprimitives.dll", "MSVCR*.dll"
)

filter IsSystemDll { foreach ($p in $systemDllPatterns) { if ($_ -like $p) { return $true } } return $false }

# Build DLL index from deps directory with a SINGLE recursive scan (max depth 4).
# Never scan PATH — it includes C:\Windows\system32 and VS dirs which
# would make Get-ChildItem -Recurse hang or take minutes.
$dllIndex = @{}
foreach ($baseDir in @($depsRoot, "$env:TOOLS_PATH\deps")) {
    if (-not $baseDir -or -not (Test-Path $baseDir)) { continue }
    Get-ChildItem -Path $baseDir -Recurse -Depth 3 -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $dllIndex.ContainsKey($_.Name)) {
            $dllIndex[$_.Name] = $_.FullName
        }
    }
}
if ($dllIndex.Count -gt 0) {
    info "Found $($dllIndex.Count) DLLs in deps directory"
}

# Use dumpbin to list imports, then copy matching non-system DLLs from the index
$dumpbinPath = (Get-Command dumpbin.exe -ErrorAction SilentlyContinue).Source
$copiedCount = 0
if ($dumpbinPath) {
    info "Using dumpbin to analyze imports"
    $importsRaw = & $dumpbinPath /dependents "$extdir\php_$ExtName.dll" 2>&1
    $imports = ($importsRaw | Select-String '^\s+(\S+\.dll)' -AllMatches).Matches |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $notFound = @()
    foreach ($dll in $imports) {
        if ($dll | IsSystemDll) { continue }
        if (Test-Path "$phppath\$dll") { continue }
        if ($dllIndex.ContainsKey($dll)) {
            info "Copy dep DLL: $dll -> $phppath"
            Copy-Item $dllIndex[$dll] $phppath
            $copiedCount++
        } else {
            $notFound += $dll
        }
    }
    if ($copiedCount -gt 0) {
        info "Copied $copiedCount dependency DLL(s)"
    }
    if ($notFound.Count -gt 0) {
        warn "DLL(s) not found in deps: $($notFound -join ', ')"
    }
} else {
    warn "dumpbin not available, copying all non-system DLLs from index"
    foreach ($kv in $dllIndex.GetEnumerator()) {
        if (($kv.Key | IsSystemDll) -or (Test-Path "$phppath\$($kv.Key)")) { continue }
        info "Copy dep DLL: $($kv.Key) -> $phppath"
        Copy-Item $kv.Value $phppath
        $copiedCount++
    }
}

$ext_ini = ""
if($Enable){
    $ext_ini = "extension=$ExtName"
}

try{
    $ini = Get-Content $inipath
}catch{
    $ini = ""
}

$match = $ini | Select-String -Pattern ('^\s*extension\s*=\s*["' + "'" + "]*$ExtName['" + '"' + ']*\s*')
if($match.Matches){
    warn ("Ini entry extension=$ExtName is already setted at $inipath line" + $match.LineNumber + ", skipping ini modification")
}elseif($Enable -Or ($extdir_ini -Ne "")){
    info ("Append `"$extdir_ini`", `"$ext_ini`" to " + $inipath)
    $content = "
$extdir_ini
$ext_ini
"
    $content | Out-File -Encoding utf8 -Append $inipath
}

# Verify DLL dependencies are resolvable
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DLL DEPENDENCY VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$checkOk = $true
if ($dumpbinPath) {
    $verifyRaw = & $dumpbinPath /dependents "$extdir\php_$ExtName.dll" 2>&1
    $allImports = ($verifyRaw | Select-String '^\s+(\S+\.dll)' -AllMatches).Matches |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    $missingDlls = @()
    foreach ($dll in $allImports) {
        if ($dll | IsSystemDll) { continue }
        if (-not (Test-Path "$phppath\$dll")) {
            $missingDlls += $dll
        }
    }

    if ($missingDlls.Count) {
        Write-Host "`nMISSING DLLs:" -ForegroundColor Red
        $missingDlls | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        err "Cannot load swoole: $($missingDlls.Count) DLL(s) not found in $phppath"
        $checkOk = $false
    } else {
        Write-Host "`nAll $($allImports.Count) dependency DLLs resolved" -ForegroundColor Green
    }
} else {
    Write-Host "dumpbin not available, skipping dependency verification" -ForegroundColor Yellow
}

if (!$checkOk) {
    Set-Location $origwd
    exit 1
}

$define = ""
if (!$Enable){
    $define = "-dextension=$ExtName"
}

php -m

info "Run 'php $define --ri $ExtName'"
& $PhpBin $define --ri $ExtName
if(0 -Ne $lastexitcode){
    exit 1
}

Set-Location $origwd

exit 0
