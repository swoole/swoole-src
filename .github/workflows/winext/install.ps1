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

# Swoole DLL Load Diagnostic Script
$ErrorActionPreference = "Continue"
$OutputDir = "$env:TEMP\swoole_debug"
$ProcMonLog = "$OutputDir\procmon_log.pml"
$ProcMonCsv = "$OutputDir\procmon_log.csv"

# 创建输出目录
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SWOOLE DLL LOADING DIAGNOSTIC" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. 下载 Process Monitor
Write-Host "`n[1/5] Downloading Process Monitor..." -ForegroundColor Yellow
$ProcMonUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"
$ProcMonZip = "$OutputDir\ProcessMonitor.zip"
$ProcMonExe = "$OutputDir\Procmon.exe"

try {
    Invoke-WebRequest -Uri $ProcMonUrl -OutFile $ProcMonZip -ErrorAction Stop
    Expand-Archive -Path $ProcMonZip -DestinationPath $OutputDir -Force
    Write-Host "  ✓ Process Monitor downloaded" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Failed to download Process Monitor: $_" -ForegroundColor Red
    exit 1
}

# 2. 启动 Process Monitor 捕获
Write-Host "`n[2/5] Starting Process Monitor capture..." -ForegroundColor Yellow

# 接受 EULA
& $ProcMonExe /AcceptEula /Quiet /Minimized /BackingFile $ProcMonLog
Start-Sleep -Seconds 2

# 检查 ProcMon 是否运行
$ProcMonProcess = Get-Process -Name "Procmon" -ErrorAction SilentlyContinue
if ($ProcMonProcess) {
    Write-Host "  ✓ Process Monitor started (PID: $($ProcMonProcess.Id))" -ForegroundColor Green
} else {
    Write-Host "  ✗ Process Monitor failed to start" -ForegroundColor Red
    exit 1
}

# 3. 运行 PHP 加载 Swoole
Write-Host "`n[3/5] Attempting to load PHP with Swoole extension..." -ForegroundColor Yellow
try {
    $PhpOutput = & php -d display_startup_errors=1 -d error_reporting=-1 -d extension=swoole -r "echo 'SWOOLE_LOAD_SUCCESS';" 2>&1
    Write-Host "  PHP Output: $PhpOutput" -ForegroundColor $(if ($PhpOutput -match "SUCCESS") { "Green" } else { "Red" })
} catch {
    Write-Host "  PHP Error: $_" -ForegroundColor Red
}

# 等待文件操作完成
Start-Sleep -Seconds 3

# 4. 停止 Process Monitor
Write-Host "`n[4/5] Stopping Process Monitor and analyzing logs..." -ForegroundColor Yellow
& $ProcMonExe /Terminate
Start-Sleep -Seconds 2

# 检查日志文件
if (Test-Path $ProcMonLog) {
    $LogSize = (Get-Item $ProcMonLog).Length / 1MB
    Write-Host "  ✓ Process Monitor log saved ($([math]::Round($LogSize, 2)) MB)" -ForegroundColor Green
} else {
    Write-Host "  ✗ Process Monitor log not found" -ForegroundColor Red
    exit 1
}

# 5. 转换日志为 CSV 并分析
Write-Host "`n[5/5] Analyzing DLL loading events..." -ForegroundColor Yellow

# 转换 PML 到 CSV
Write-Host "  Converting log to CSV format..."
try {
    & $ProcMonExe /OpenLog $ProcMonLog /SaveAs $ProcMonCsv
    Start-Sleep -Seconds 5

    if (Test-Path $ProcMonCsv) {
        Write-Host "  ✓ CSV export completed" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ CSV export may have failed, trying alternative analysis..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠ CSV conversion error: $_" -ForegroundColor Yellow
}

# 分析结果
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ANALYSIS RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Test-Path $ProcMonCsv) {
    # 导入 CSV 并过滤相关事件
    Write-Host "`n--- DLL Load Events ---" -ForegroundColor Green

    $Events = Import-Csv $ProcMonCsv | Where-Object {
        $_.Operation -match "Load Image|CreateFile" -and
        ($_.Path -match "swoole|php8ts|libssl|libcrypto|nghttp2|libzstd|brotli|MSVCP|VCRUNTIME") -and
        ($_.ProcessName -match "php")
    }

    # 分析失败的事件
    $FailedLoads = $Events | Where-Object { $_.Result -ne "SUCCESS" }

    if ($FailedLoads) {
        Write-Host "`n✗ FAILED DLL LOADS:" -ForegroundColor Red
        $FailedLoads | Select-Object "Time of Day", Path, Result, Detail | Format-Table -AutoSize

        Write-Host "`nMissing DLLs:" -ForegroundColor Yellow
        $FailedLoads | ForEach-Object {
            $dllName = Split-Path $_.Path -Leaf
            if ($_.Result -match "NAME NOT FOUND|PATH NOT FOUND") {
                Write-Host "  • $dllName (searched in $(Split-Path $_.Path))" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  ✓ No failed DLL loads detected" -ForegroundColor Green
    }

    # 成功的加载
    $SuccessfulLoads = $Events | Where-Object { $_.Result -eq "SUCCESS" }
    if ($SuccessfulLoads) {
        Write-Host "`n✓ SUCCESSFUL DLL LOADS:" -ForegroundColor Green
        $SuccessfulLoads | Select-Object "Time of Day", Path | Format-Table -AutoSize
    }

    # 导出详细报告
    $ReportFile = "$OutputDir\swoole_dll_report.txt"
    Write-Host "`n--- Generating Detailed Report ---" -ForegroundColor Yellow

    @"
=====================================
SWOOLE DLL LOADING DIAGNOSTIC REPORT
=====================================
Generated: $(Get-Date)

FAILED DLL LOADS:
------------------
$($FailedLoads | ForEach-Object { "$($_.'Time of Day') - $($_.Path) - $($_.Result) - $($_.Detail)" } | Out-String)

SUCCESSFUL DLL LOADS:
---------------------
$($SuccessfulLoads | ForEach-Object { "$($_.'Time of Day') - $($_.Path)" } | Out-String)

ALL PHP-RELATED EVENTS:
----------------------
$($Events | Select-Object "Time of Day", Operation, Path, Result | Format-Table -AutoSize | Out-String)
"@ | Out-File -FilePath $ReportFile -Encoding UTF8

    Write-Host "  ✓ Detailed report saved to: $ReportFile" -ForegroundColor Green
}
else {
    # 如果 CSV 不可用，尝试直接文本分析
    Write-Host "`nAttempting alternative analysis..." -ForegroundColor Yellow

    # 手动检查已知需要的 DLLs
    Write-Host "`n--- Manual DLL Check ---" -ForegroundColor Yellow

    $RequiredDlls = @(
        "libssl-3-x64.dll",
        "libcrypto-3-x64.dll",
        "nghttp2.dll",
        "libzstd.dll",
        "brotlienc.dll",
        "brotlidec.dll",
        "php8ts.dll",
        "MSVCP140.dll",
        "VCRUNTIME140.dll"
    )

    $PhpDir = "C:\tools\php"
    $MissingDlls = @()

    foreach ($dll in $RequiredDlls) {
        $Found = $false
        $Locations = @(
            "$PhpDir\$dll",
            "$PhpDir\ext\$dll",
            "C:\Windows\System32\$dll",
            "C:\Windows\SysWOW64\$dll",
            "C:\tools\phpdev\$dll"
        )

        foreach ($loc in $Locations) {
            if (Test-Path $loc) {
                Write-Host "  ✓ $dll found at: $loc" -ForegroundColor Green
                $Found = $true
                break
            }
        }

        if (-not $Found) {
            Write-Host "  ✗ $dll MISSING" -ForegroundColor Red
            $MissingDlls += $dll
        }
    }

    if ($MissingDlls.Count -gt 0) {
        Write-Host "`n⛔ CRITICAL: Missing $( $MissingDlls.Count ) required DLL(s)!" -ForegroundColor Red
        Write-Host "Missing files:" -ForegroundColor Red
        $MissingDlls | ForEach-Object { Write-Host "  • $_" -ForegroundColor Red }
    }
}

# 清理
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All diagnostic files saved to: $OutputDir" -ForegroundColor Yellow
Write-Host "  - Process Monitor log: $ProcMonLog" -ForegroundColor Gray
if (Test-Path $ProcMonCsv) {
    Write-Host "  - CSV export: $ProcMonCsv" -ForegroundColor Gray
}
Write-Host "  - Detailed report: $ReportFile" -ForegroundColor Gray

# 提示下一步
Write-Host "`nℹ To view the Process Monitor log interactively:" -ForegroundColor Cyan
Write-Host "  $ProcMonExe /OpenLog $ProcMonLog" -ForegroundColor White

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
