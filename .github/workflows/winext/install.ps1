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

$define = ""
if (!$Enable){
    $define = "-dextension=$ExtName"
}

php -m

# ========================================
# Check DLL dependencies using dumpbin
# ========================================
echo ""
echo "=== [1] Checking DLL dependencies with dumpbin ==="
$swoole_dll = "$extdir\php_$ExtName.dll"
if (Test-Path $swoole_dll) {
    $swoole_dll = (Resolve-Path $swoole_dll).Path
    dumpbin /dependents $swoole_dll 2>&1 | Select-Object -First 30
} else {
    err "php_$ExtName.dll not found at $extdir"
}

echo ""
echo "=== [2] Get DLL dependencies from dumpbin ==="
$dep_dlls = @()
if (Test-Path $swoole_dll) {
    $dumpbin_output = dumpbin /dependents $swoole_dll 2>&1
    # Parse DLL names from dumpbin output (skip header lines, get .dll names)
    $dep_dlls = $dumpbin_output | Select-Object -Skip 3 | Where-Object { $_ -match '\.dll$' } | ForEach-Object {
        $_.Trim()
    }
    echo "Required DLLs:"
    $dep_dlls | ForEach-Object { echo "  $_" }
} else {
    err "php_$ExtName.dll not found at $extdir"
}

echo ""
echo "=== [3] Check DLLs in PATH ==="
$missing_count = 0
$missing_dlls = @()
$search_paths = $env:PATH.Split(';') + @("$env:PHP_DIR\lib", "$env:PHP_DIR\bin", "C:\Windows\System32")
$search_paths = $search_paths | Select-Object -Unique

foreach ($dll in $dep_dlls) {
    $found = $false
    foreach ($path in $search_paths) {
        if ($path -and (Test-Path "$path\$dll" -PathType Leaf)) {
            $found = $true
            break
        }
    }
    if (-not $found) {
        warn "MISSING: $dll"
        $missing_count++
        $missing_dlls += $dll
    }
}

echo ""
if ($missing_count -eq 0) {
    info "All DLL dependencies found in PATH"
} else {
    warn "Total missing: $missing_count DLLs"
    echo ""
    echo "Searching for missing DLLs:"
    foreach ($dll in $missing_dlls) {
        echo "  Looking for: $dll"
        foreach ($path in $search_paths) {
            if ($path -and (Test-Path $path)) {
                $matches = Get-ChildItem $path -Filter "*$dll*" -ErrorAction SilentlyContinue
                if ($matches) {
                    $matches | ForEach-Object { echo "    Found: $($_.Name) in $path" }
                }
            }
        }
    }
}

echo ""
echo "=== [4] Environment Info ==="
echo "PHP_DIR: $env:PHP_DIR"
echo "PHP_EXTENSION_DIR: $extdir"
echo "PATH entries:"
$env:PATH.Split(';') | Where-Object { $_ } | ForEach-Object { echo "  $_" }

echo ""
echo "=== [5] Attempting to load Swoole ==="
php -d display_startup_errors=1 -d error_reporting=-1 -d extension=swoole -r "echo 'Swoole loaded successfully!';" 2>&1
$load_result = $LASTEXITCODE

if ($load_result -eq 0) {
    info "Run 'php --ri $ExtName'"
    & $PhpBin -dextension=swoole --ri $ExtName
    if (0 -Ne $lastexitcode) {
        Set-Location $origwd
        exit 1
    }
} else {
    err "Failed to load swoole extension"
    Set-Location $origwd
    exit 1
}

Set-Location $origwd

exit 0
