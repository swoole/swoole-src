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

info "Run 'php $define --ri $ExtName'"
& $PhpBin $define --ri $ExtName
if(0 -Ne $lastexitcode){
    exit 1
}

Set-Location $origwd

exit 0