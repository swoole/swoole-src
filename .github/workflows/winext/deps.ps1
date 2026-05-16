# php deps downloader

param (
    [Object[]]$DllDeps,
    [int]$MaxTry = 3,
    [string]$ToolsPath = "C:\tools\phpdev",
    [string]$PhpBin = "php",
    [string]$PhpVer = "",
    [string]$PhpVCVer = "",
    [string]$PhpArch = "x64",
    [bool]$Staging = $false,
    [bool]$PhpTs = $false,
    [bool]$DryRun = $false
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "deps" -MaxTry $MaxTry

if($DllDeps.Length -Lt 1){
    warn "No deps specified, just skipped."
    exit 0
}

# things we used later
if ("".Equals($PhpVer)){
    try{
        $PhpVer = & $PhpBin -r "echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . PHP_EOL;"
        $phpinfo = & $PhpBin -i
        $PhpVCVer = ($phpinfo | Select-String -Pattern 'PHP Extension Build => .+,(.+)' -CaseSensitive -List).Matches.Groups[1]
        $PhpArch = ($phpinfo | Select-String -Pattern 'Architecture => (.+)' -CaseSensitive -List).Matches.Groups[1]
    }finally{
        if(
            !$PhpVer -Or
            !$PhpVCVer -Or
            !$PhpArch
        ){
            err "Cannot determine php attributes, do you have php in PATH?"
            warn "phpver: $PhpVer"
            warn "phpvcver: $PhpVCVer"
            warn "phparch: $PhpArch"
            exit 1
        }
    }
}

$PhpVCVer = $PhpVCVer.ToLower()

info "Try to fetch deps series list from https://downloads.php.net/~windows"
if($Staging){
    $stagingStr = "staging"
}else{
    $stagingStr = "stable"
}
$seriesUrl = "https://downloads.php.net/~windows/php-sdk/deps/series/packages-$PhpVer-$PhpVCVer-$PhpArch-$stagingStr.txt"
info "Series URL: $seriesUrl"
$series = (fetchpage $seriesUrl).Content
if(!$series){
    err "Cannot get series information from https://downloads.php.net/~windows"
    exit 1
    # filelist may not match php distro, so disable it
    # $filelist = (fetchpage ("https://downloads.php.net/~windows/php-sdk/deps/" + $PhpVCVer.ToLower() + "/$PhpArch/")).Content
    # if(!$filelist){
    #     err "Neither series file nor file list can be got, aborting"
    #     exit 1
    # }
}

$downloadeddeps = [System.Collections.ArrayList]@()
foreach ($depname in $DllDeps) {
    $depfile = $null
    if($series){
        foreach ($filename in $series.Split()) {
            if($filename.StartsWith($depname)){
                info "Found file $filename for dep $depname"
                $depfile = $filename
                break
            }
        }
    }else{
        $fnver = searchfile $filelist -Pattern ("$depname-:-" + $PhpVCVer.ToLower() + "-$PhpArch.zip")
        $depfile = $fnver[0]
    }

    if(!$depfile){
        err "Cannot find dep file for $depname"
        exit 1
    }
    $downloadeddeps.Add($depfile) | Out-Null
    if($DryRun){
        continue
    }

    info "Downloading $filename from https://downloads.php.net/~windows"
    provedir "$ToolsPath"
    provedir "$ToolsPath\deps"
    $dest = "$ToolsPath\deps\$depfile"
    if(Test-Path $dest -PathType Leaf){
        warn "$depfile is already provided, instant extract it."
    }else {
        $uri = "https://downloads.php.net/~windows/php-sdk/deps/$PhpVCVer/$PhpArch/$depfile"
        $ret = dlwithhash -Uri $uri -Dest $dest
        if (!$ret){
            err "Failed download $uri."
            exit 1
        }
    }
    info "Unzipping $dest to $ToolsPath\deps\"

    Expand-Archive $dest -Destination "$ToolsPath\deps\" -Force
}

# if we are in github workflows, set downloaded as output
if(${env:CI} -Eq "true"){
    $s = ( $downloadeddeps | Sort-Object ) -Join "_"
    Write-Output "downloadeddeps=$s" | Out-File "${env:GITHUB_OUTPUT}" -Append
}

info "Done."

exit 0
