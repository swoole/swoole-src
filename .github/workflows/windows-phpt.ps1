param(
    [Parameter(Mandatory = $true)]
    [string[]] $Path,
    [int] $Offset = 0,
    [int] $Count = [int]::MaxValue,
    [int] $TimeoutSeconds = 12
)

$ErrorActionPreference = 'Stop'
$env:PHPT = '1'
$env:TEST_PHP_EXECUTABLE = 'php'
$env:SKIP_ONLINE_TESTS = '1'
$env:NO_INTERACTION = '1'

$tests = foreach ($entry in $Path) {
    $item = Get-Item -LiteralPath $entry -ErrorAction SilentlyContinue
    if ($item -and $item.PSIsContainer) {
        Get-ChildItem -LiteralPath $item.FullName -Recurse -Filter *.phpt -File
    } elseif ($item) {
        $item
    } else {
        Get-ChildItem -Path $entry -Filter *.phpt -File
    }
}

$tests = @(
    $tests |
        Sort-Object FullName -Unique |
        Select-Object -Skip $Offset -First $Count
)

if ($tests.Count -eq 0) {
    throw "No PHPT files matched: $($Path -join ', ')"
}

$innerTimeout = [Math]::Max(1, $TimeoutSeconds - 2)
$options = @(
    'tests\run-tests',
    '-P',
    '-q',
    '-d', 'extension=php_swoole',
    '-d', 'swoole.use_shortname=On',
    '--show-diff',
    '-g', 'PASS,FAIL,BORK,LEAK,XLEAK',
    '--show-slow', '1000',
    '--set-timeout', $innerTimeout
)

$failures = [System.Collections.Generic.List[string]]::new()
$timeouts = [System.Collections.Generic.List[string]]::new()

foreach ($test in $tests) {
    $relativePath = Resolve-Path -Relative $test.FullName
    Write-Host "::group::PHPT $relativePath"
    try {
        $process = Start-Process -FilePath php -ArgumentList ($options + $test.FullName) -NoNewWindow -PassThru
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timeouts.Add($relativePath)
            $failures.Add($relativePath)
            Write-Error "PHPT exceeded ${TimeoutSeconds}s: $relativePath" -ErrorAction Continue
            & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null
            $process.WaitForExit()
        } else {
            $process.Refresh()
            if ($process.ExitCode -ne 0) {
                $failures.Add($relativePath)
                Write-Error "PHPT failed with exit code $($process.ExitCode): $relativePath" -ErrorAction Continue
            }
        }
    } finally {
        Write-Host '::endgroup::'
    }
}

Write-Host "Windows PHPT summary: $($tests.Count - $failures.Count) passed/skipped, $($failures.Count) failed, $($timeouts.Count) timed out"
if ($failures.Count -gt 0) {
    Write-Host "Failed PHPT: $($failures -join ', ')"
    exit 1
}
