# dll release uploader (via artifact)

param (
    [int]$MaxTry=3,
    [string]$Repo,
    [string]$RelID,
    [string]$Token,
    [string]$AttestationBundle = ""
)

$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
. "$scriptPath\utils.ps1" -ToolName "uploader" -MaxTry $MaxTry

# gh api headers
$headers = @{
    "accept"="application/vnd.github.v3+json";
    "content-type"="application/json";
    "authorization"="Bearer ${Token}";
}

if(-Not $Repo -Or -Not $Token -Or -Not $RelID){
    err "Needs repo name and gh token to work."
    #exit 1
}

$RelInfo = fetchjson `
    -Uri "https://api.github.com/repos/$Repo/releases/$RelID" `
    -Headers $headers
if(!$RelInfo){
    err "Failed fetch release information"
    return
}

$match = $RelInfo."upload_url" | Select-String -Pattern "(?<url>(?:http|https)://.+)(?<arg>\{.+\})"
$uploadUrl = ($match.Matches[0].Groups["url"]).ToString() + "?name="

$RunID = $null
$jobdata = $null

$note = "`n## Hashes and notes`n`n" + `
    "| File name | Size (in bytes) | SHA256 sum | Build log | Tests result |`n" + `
    "| - | - | - | - | - |`n"

# read all jsons for all dlls
Get-ChildItem . | Sort-Object -Property Name | ForEach-Object -Process {
    if($_.Name.EndsWith(".dll")){
        $fn = $_.Name
        $jsonfn = "${fn}.json"
        $pdbfn = $fn.replace('.dll', '.pdb')
        if (-Not (Test-Path $jsonfn -Type Leaf)){
            continue
        }
        info "Read information from $jsonfn"
        $data = Get-Content $jsonfn | ConvertFrom-Json
        if($fn -Ne $data.name){
            warn "Not same filename, bad json, skip it"
            continue
        }
        if(-Not $RunID){
            $RunID = $data.runid
            $jobdata = (fetchjson `
                -Headers $headers `
                -Uri "https://api.github.com/repos/$Repo/actions/runs/$RunID/jobs")."jobs"
        }else{
            if ($RunID -Ne $data.runid){
                warn "Not same runid, bad json, skip it"
                continue
            }
        }
        if((Get-FileHash -Algorithm SHA256 $fn).Hash -Ne $data.hash){
            warn "Bad dll hash, skip it"
            continue
        }
        $link = $null
        foreach($job in $jobdata) {
            if($job.name.ToString().Contains($data.jobname)){
                $link = $job."html_url"
                info "Workflow run link is $link"
            }
        }
        $linkstr = "[link](${link})"
        if(-Not $link){
            warn "Not found work run, strange"
            $linkstr = "-"
        }
        info "Uploading file $fn"
        $ret = Invoke-WebRequest `
            -Uri "$uploadUrl$fn" `
            -Method "POST" `
            -ContentType "application/zip" `
            -Headers $headers `
            -InFile $fn
        if(-Not $ret){
            warn "Failed to upload $fn"
            continue
        }
        info "Uploading file $pdbfn"
        $ret = Invoke-WebRequest `
            -Uri "$uploadUrl$pdbfn" `
            -Method "POST" `
            -ContentType "application/zip" `
            -Headers $headers `
            -InFile $pdbfn
        if(-Not $ret){
            warn "Failed to upload $pdbfn"
            continue
        }
        $size = $data.size
        $hash = $data.hash
        $result = $data.result
        $note += "| ${fn} | ${size} | ${hash} | ${linkstr} | ${result} |`n"

        # build PIE zip
        $zipfn = $fn.replace('.dll', '.zip')
        info "Building PIE zip $zipfn"
        & 7z a -tzip -mx=9 $zipfn `
            $fn `
            $pdbfn `
            LICENSE `
            LICENSES.full `

        info "Uploading PIE zip $zipfn"
        $ret = Invoke-WebRequest `
            -Uri "$uploadUrl$zipfn" `
            -Method "POST" `
            -ContentType "application/zip" `
            -Headers $headers `
            -InFile $zipfn
        if(-Not $ret){
            warn "Failed to upload $zipfn"
            continue
        }
    }
}

if ($AttestationBundle) {
    info "Uploading Attestation bundle $AttestationBundle"
    $ret = Invoke-WebRequest `
        -Uri "${uploadUrl}attestation.jsonl" `
        -Method "POST" `
        -ContentType "application/json" `
        -Headers $headers `
        -InFile $AttestationBundle
    if(-Not $ret){
        warn "Failed to upload $AttestationBundle"
        continue
    }
}

info "Fetching original notes"
$note = $RelInfo.body.ToString() + $note
$patch = @{
    "body"="$note";
} | ConvertTo-Json -Compress

info "Repost note"
$ret = fetchjson `
    -Body $patch `
    -Method "PATCH" `
    -Uri "https://api.github.com/repos/$Repo/releases/$RelID" `
    -Headers $headers
if (-Not $ret){
    err "Failed patch notes"
    exit 1
}

info Done

