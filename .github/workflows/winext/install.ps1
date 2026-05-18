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
if (-not $depsRoot) { $depsRoot = "$ToolsPath\deps" }
$searchDirs = @(
    if ($depsRoot -and (Test-Path $depsRoot)) { $depsRoot }
    if (Test-Path "$ToolsPath\deps") { "$ToolsPath\deps" }
    $phppath
    $extdir
) + ($env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) })

$systemDllPatterns = @(
    "KERNEL32.dll", "ADVAPI32.dll", "SHELL32.dll", "ole32.dll", "OLEAUT32.dll",
    "USER32.dll", "GDI32.dll", "WS2_32.dll", "IPHLPAPI.DLL", "CRYPT32.dll",
    "VCRUNTIME*.dll", "MSVCP*.dll", "CONCRT*.dll", "VCOMP*.dll",
    "api-ms-win-*", "ext-ms-win-*", "ntdll.dll", "bcrypt.dll", "Secur32.dll",
    "VERSION.dll", "WINMM.dll", "WLDAP32.dll", "NORMALIZ.dll", "NETAPI32.dll",
    "ucrtbase.dll", "bcryptprimitives.dll", "MSVCR*.dll"
)

filter IsSystemDll { foreach ($p in $systemDllPatterns) { if ($_ -like $p) { return $true } } return $false }

function FindAndCopyDll($dllName) {
    foreach ($dir in $script:searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        $found = Get-ChildItem -Path $dir -Recurse -Filter $dllName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found -and -not (Test-Path "$script:phppath\$dllName")) {
            info "Copy dep DLL: $($found.Name) -> $script:phppath"
            Copy-Item $found.FullName $script:phppath
            return $true
        }
    }
    return $false
}

$dumpbin = (Get-Command dumpbin.exe -ErrorAction SilentlyContinue).Source
$copiedCount = 0
if ($dumpbin) {
    $importsRaw = & $dumpbin /dependents "$extdir\php_$ExtName.dll" 2>&1
    $imports = ($importsRaw | Select-String '^\s+(\S+\.dll)' -AllMatches).Matches |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $notFound = @()
    foreach ($dll in $imports) {
        if ($dll | IsSystemDll) { continue }
        if (Test-Path "$phppath\$dll") { continue }
        if (FindAndCopyDll $dll) { $copiedCount++ } else { $notFound += $dll }
    }
    if ($copiedCount -gt 0) {
        info "Copied $copiedCount dependency DLL(s)"
    }
    if ($notFound.Count -gt 0) {
        warn "DLL(s) not found in deps: $($notFound -join ', ')"
    }
} else {
    warn "dumpbin not available, copying all non-system DLLs from deps directory"
    foreach ($dir in $searchDirs) {
        Get-ChildItem -Path $dir -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object {
            if (($_.Name | IsSystemDll) -or (Test-Path "$phppath\$($_.Name)")) { return }
            info "Copy dep DLL: $($_.Name) -> $phppath"
            Copy-Item $_.FullName $phppath
            $script:copiedCount++
        }
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
if ($dumpbin) {
    # Re-read imports for verification (list may differ after copies)
    $verifyRaw = & $dumpbin /dependents "$extdir\php_$ExtName.dll" 2>&1
    $allImports = ($verifyRaw | Select-String '^\s+(\S+\.dll)' -AllMatches).Matches |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    $foundDlls = @()
    $missingDlls = @()
    foreach ($dll in $allImports) {
        if ($dll | IsSystemDll) { continue }
        $located = Test-Path "$phppath\$dll"
        if (-not $located) {
            foreach ($dir in ($env:PATH -split ';')) {
                if ($dir -and (Test-Path "$dir\$dll")) { $located = $true; break }
            }
        }
        if ($located) { $foundDlls += $dll } else { $missingDlls += $dll }
    }

    if ($foundDlls.Count) {
        Write-Host "`nResolved DLLs:" -ForegroundColor Green
        $foundDlls | ForEach-Object { Write-Host "  $_" -ForegroundColor Green }
    }
    if ($missingDlls.Count) {
        Write-Host "`nMISSING DLLs:" -ForegroundColor Red
        $missingDlls | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        err "Cannot load swoole: $($missingDlls.Count) DLL(s) not found. Check PATH or deps."
        $checkOk = $false
    } else {
        Write-Host "`nAll dependency DLLs resolved" -ForegroundColor Green
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
