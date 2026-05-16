# php dev-pack downloader

param (
    [int]$MaxTry = 3,
    [string]$ToolsPath = "C:\tools\phpdev",
    [string]$PhpBin = "php",
    [string]$PhpVer = "",
    [string]$PhpVCVer = "",
    [string]$PhpArch = "x64",
    [bool]$PhpTs = $false,
    [bool]$DryRun = $false
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "devpack" -MaxTry $MaxTry

if ("".Equals($PhpVer)){
    try{
        $PhpVer = & $PhpBin -r "echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . PHP_EOL;"
        $phpinfo = & $PhpBin -i
        $PhpVCVer = ($phpinfo | Select-String -Pattern 'PHP Extension Build => .+,(.+)' -CaseSensitive -List).Matches.Groups[1]
        $PhpArch = ($phpinfo | Select-String -Pattern 'Architecture => (.+)' -CaseSensitive -List).Matches.Groups[1]
        $phpvar = & $PhpBin -r "echo (PHP_ZTS?'':'n') . 'ts-$PhpVCVer-$PhpArch' . PHP_EOL;"
        $dashnts = & $PhpBin -r "echo (PHP_ZTS?'':'-nts') . PHP_EOL;"
        $underscorets = & $PhpBin -r "echo (PHP_ZTS?'_TS':'') . PHP_EOL;"
    }finally{
    }
}else{
    if($PhpTs){
        $phpvar = "ts-$PhpVCVer-$PhpArch"
        $dashnts = ""
        $underscorets = "_TS"
    }else{
        $phpvar = "nts-$PhpVCVer-$PhpArch"
        $dashnts = "-nts"
        $underscorets = ""
    }
}
if(
    !$PhpVer -Or
    !$PhpVCVer -Or
    !$PhpArch -Or
    !$phpvar
){
    err "Cannot determine php attributes, do you have php in PATH?"
    err "You can also specify vals via arguments"
    warn "phpver: $PhpVer"
    warn "phpvcver: $PhpVCVer"
    warn "phparch: $PhpArch"
    warn "phpvar: $phpvar"
    exit 1
}

# Check if devpack directory already exists (e.g., restored from cache)
$sa = New-Object -ComObject Shell.Application
$devpackPattern = "php-" + $PhpVer + ".*-devel-" + $PhpVCVer + "-" + $PhpArch
$existingDevpack = Get-ChildItem $ToolsPath -Directory | Where-Object { $_.Name -like $devpackPattern } | Select-Object -First 1
if ($existingDevpack -And (Test-Path "$ToolsPath\$($existingDevpack.Name)\script\phpize.js")) {
    info "Found existing devpack directory: $($existingDevpack.Name), skipping download."
    $dirname = $existingDevpack.Name
    if($DryRun){
        return
    }
    goto :generate_env
}

function fetchdevpack(){
    if ($info.$PhpVer.$phpvar) {
        info "Found target version on releases, try using latest devpack."
        $latest = $info.$PhpVer.$phpvar."devel_pack"
        # if we are in github workflows, set ver as output
        if(${env:CI} -Eq "true"){
            Write-Output ("devpackver=" + $info.$PhpVer."version") | Out-File "${env:GITHUB_OUTPUT}" -Append
        }
        if($DryRun){
            return
        }

        if($latest.sha1){
            $hash = $latest.sha1
            $hashmethod = "SHA1"
        }elseif($latest.sha256){
            $hash = $latest.sha256
            $hashmethod = "SHA256"
        }else{
            warn "No hash for this file provided or not supported."
        }
        $dest = "$ToolsPath\" + ($latest.path)

        if($hashmethod -And (Test-Path $dest -PathType Leaf)){
            if($hashmethod -And $hash -Eq (Get-FileHash $dest -Algorithm $Hashmethod).Hash){
                warn "$dest is already provided, skipping downloading."
                return $dest
            }
        }

        provedir $ToolsPath
        $ret = dlwithhash `
            -Uri ("https://downloads.php.net/~windows/releases/" + ($latest.path)) `
            -Dest $dest `
            -Hash $hash `
            -Hashmethod $hashmethod
        if ($ret){
            return $dest
        }
    } else {
        info "Target version is not active release or failed to download releases info, try search in file list."
        try{
            $page = fetchpage "https://downloads.php.net/~windows/releases/archives/"
            $groups = ($page | Select-String `
                -List `
                -AllMatches `
                -Pattern ('<A HREF="[^"]+?">(?:php-devel-pack-' + $PhpVer + '.(?:\d+)' + $dashnts +'-Win32-' + $PhpVCVer + '-' + $PhpArch + '.zip)</A>')).Matches.Groups
            $used = 0
            foreach ($item in $groups) {
                $minor = ($item | Select-String -Pattern ($PhpVer + '.(\d+)')).Matches.Groups[1].ToString() -As "int"
                if ($minor -Gt $used){
                    $used = $minor
                }
            }
            $fn = 'php-devel-pack-' + $PhpVer + '.' + $used + $dashnts +'-Win32-' + $PhpVCVer + '-' + $PhpArch + '.zip'
            # if we are in github workflows, set ver as output
            if(${env:CI} -Eq "true"){
                Write-Output "devpackver=$PhpVer.$used" | Out-File "${env:GITHUB_OUTPUT}" -Append
            }
        }catch [System.Net.WebException],[System.IO.IOException]{
            warn "Cannot fetch archives list, use oldest instead"
            Write-Host $_
            $fn = 'php-devel-pack-' + $PhpVer + '.0' + $dashnts +'-Win32-' + $PhpVCVer + '-' + $PhpArch + '.zip'
            # if we are in github workflows, set ver as output
            if(${env:CI} -Eq "true"){
                Write-Output "devpackver=$PhpVer.0" | Out-File "${env:GITHUB_OUTPUT}" -Append
            }
        }
        if($DryRun){
            return
        }
        #Write-Host $fn
        provedir $ToolsPath
        $ret = dlwithhash -Uri "https://downloads.php.net/~windows/releases/archives/$fn" -Dest "$ToolsPath\$fn"
        if ($ret){
            return "$ToolsPath\$fn"
        }
    }
}

info "Finding devpack for PHP $PhpVer $phpvar"
$info = fetchjson -Uri "https://downloads.php.net/~windows/releases/releases.json"
if(!$info){
    warn "Cannot fetch php releases info from https://downloads.php.net/~windows."
}
$zipdest = fetchdevpack
if($DryRun){
    return
}
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

:generate_env
info "Try patch phpize.js for newer wscript"
# see https://github.com/php/php-src/commit/7f6c05116e83e75353f27f5333cc860c3a6f64f7
$phpizejs = Get-Content "$ToolsPath\$dirname\script\phpize.js"
$phpizejs = $phpizejs -Replace "var c, i, ok, n;", "var c, i, ok, n=`"`";"
[IO.File]::WriteAllLines("$ToolsPath\$dirname\script\phpize.js", $phpizejs)

info "Done unzipping devpack, generate env.bat."

# Since setup-php only provides Release version PHP, yet we only support Release
# Maybe sometimes we can build PHP by ourself?
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
