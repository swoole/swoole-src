# create a gh release

param (
    [string]$Token,
    [string]$Repo,
    [string]$TagName,
    [string]$body,
    [bool]$prerelease=$false,
    [bool]$draft=$true
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "release" -MaxTry 1

if(-Not $Repo -Or -Not $TagName -Or -Not $Token){
    err "Needs repo, release tagname and gh token to work."
    exit 1
}

# gh api headers
$headers = @{
    "accept"="application/vnd.github.v3+json";
    "content-type"="application/json";
    "authorization"="Bearer ${Token}";
}
try {
    $ret = fetchjson `
        -Uri "https://api.github.com/repos/$Repo/releases/tags/$TagName" `
        -Headers $headers
} catch {
}
if(!$ret){
    $data = @{
        "tag_name"=$TagName;
        "name"=$TagName;
        "body"=$body;
        "draft"=$true;
        "prerelease"=$true;
    }
    $ret = fetchjson `
        -Body ($data | ConvertTo-Json -Compress) `
        -Method "POST" `
        -Uri "https://api.github.com/repos/$Repo/releases" `
        -Headers $headers
    if(!$ret){
        err "Failed create release"
        exit 1
    }
}

Write-Output ("upload_url=" + $ret."upload_url") | Out-File "${env:GITHUB_OUTPUT}" -Append
Write-Output ("id=" + $ret."id") | Out-File "${env:GITHUB_OUTPUT}" -Append
