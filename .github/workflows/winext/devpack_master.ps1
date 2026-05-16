# php dev-pack downloader from shivammathur/php-builder-windows

param (
    [int]$MaxTry = 3,
    [string]$ToolsPath = "C:\tools\phpdev",
    [string]$PhpArch = "x64",
    [string]$PhpVCVer = "vs16",
    [bool]$PhpTs = $false,
    [string]$Release = "master"
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "devpack-master" -MaxTry $MaxTry

if($PhpTs){
    $nts = "ts"
    $underscorets = "_TS"
}else{
    $nts = "nts"
    $underscorets = ""
}

function fetchdevpack(){
    info "Fetching php master dev pack from shivammathur/php-builder-windows"
    provedir $ToolsPath

    $VCVer = $PhpVCVer.ToLower()
    $fn = "php-debug-pack-master-$nts-Win32-$VCVer-$PhpArch.zip"
    $ret = dlwithhash -Uri "https://github.com/shivammathur/php-builder-windows/releases/download/$Release/php-devel-pack-master-$nts-windows-$VCVer-$PhpArch.zip" -Dest "$ToolsPath\$fn"
    if ($ret){
        return "$ToolsPath\$fn"
    }
}

info "Finding devpack for PHP master"
$zipdest = fetchdevpack
if (-Not $zipdest){
    err "Failed download devpack zip."
    exit 1
}

info "Done downloading devpack, unzip it."

try{
    # if possible, should we use -PassThru to get file list?
    Expand-Archive $zipdest -Destination $ToolsPath -Force | Out-Host
}catch {
    err "Cannot unzip downloaded zip $zipdest to $ToolsPath, that's strange."
    Write-Host $_
    exit 1
}
$sa = New-Object -ComObject Shell.Application
$dirname = ($sa.NameSpace($zipdest).Items() | Select-Object -Index 0).Name

info "Done unzipping devpack, generate env.bat."

$content="
@ECHO OFF
SET BUILD_DIR=$PhpArch\Release$underscorets
SET PATH=$ToolsPath\$dirname;%PATH%
SET DEVPACK_PATH=$ToolsPath\$dirname
$ToolsPath\php-sdk-binary-tools\phpsdk-starter.bat -c $PhpVCVer -a $PhpArch -t %*
"
[IO.File]::WriteAllLines("$ToolsPath\env.bat", $content)

info "Done preparing dev-pack"

exit 0
