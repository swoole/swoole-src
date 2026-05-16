# cafile workaround: set cafile for cURL and OpenSSL

param (
    [string]$PhpBin= "php",
    [int]$MaxTry= 3
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "cafile" -MaxTry $MaxTry

$phppath = ((Get-Command $PhpBin).Source | Select-String -Pattern '(.+)\\php\.exe').Matches.Groups[1].Value
$inipath = "$phppath\php.ini"

$cafile = "$phppath\ssl\cacert.pem"

New-Item -ItemType Directory -Force -Path "$phppath\ssl"
$ret = fetchpage "https://curl.se/ca/cacert.pem"
if ($ret.StatusCode -ne 200) {
    warn "Failed to download cafile from curl.se"
    exit 1
}
$content = $ret.Content
if ($content.GetType() -eq [System.Byte[]]) {
    $content = [System.Text.Encoding]::UTF8.GetString($content)
}
$content | Out-File -FilePath $cafile -Encoding ASCII

$openssl_cafile_ini = "openssl.cafile = $cafile"
$curl_cafile_ini = "curl.cainfo = $cafile"
info ("Append `"$curl_cafile_ini`", `"$openssl_cafile_ini`" to " + $inipath)
$content = "
$curl_cafile_ini
$openssl_cafile_ini

"
$content | Out-File -Append $inipath -Encoding ASCII # for no BOM
