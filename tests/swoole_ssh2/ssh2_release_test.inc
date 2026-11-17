<?php

/** Run a child with the same PHP build, INI arguments and extension as the PHPT runner. */
function ssh2t_run_with_native_audit(string $script, bool $failFree = false): void
{
    $directory = sys_get_temp_dir() . '/swoole-ssh2-audit-' . bin2hex(random_bytes(8));
    if (!mkdir($directory)) {
        throw new RuntimeException('Failed to create the SSH2 audit directory.');
    }
    $library = $directory . '/audit.so';
    $report = $directory . '/counters';
    try {
        $command = 'cc -shared -fPIC -std=c99 -o ' . escapeshellarg($library) . ' '
            . escapeshellarg(__DIR__ . '/fixtures/release_audit.c');
        exec($command, $output, $status);
        if ($status !== 0) {
            throw new RuntimeException('Failed to build the libssh2 audit fixture.');
        }
        file_put_contents($report, str_repeat("\0", 48));
        $environment = getenv();
        // LD_AUDIT also observes bindings made with PHP's RTLD_DEEPBIND; LD_PRELOAD does not.
        $environment['LD_AUDIT'] = $library;
        $environment['SWOOLE_SSH2_AUDIT_REPORT'] = $report;
        if ($failFree) {
            $environment['SWOOLE_SSH2_FAIL_FREE'] = '1';
        } else {
            unset($environment['SWOOLE_SSH2_FAIL_FREE']);
        }
        // TEST_PHP_EXTRA_ARGS includes -n and the extension under test, not merely PHP_BINARY's defaults.
        $command = escapeshellarg(getenv('TEST_PHP_EXECUTABLE') ?: PHP_BINARY)
            . ' ' . getenv('TEST_PHP_EXTRA_ARGS')
            . ' -d report_memleaks=0 -d display_errors=1 -d log_errors=0 '
            . escapeshellarg($script) . ' child';
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $environment);
        if (!is_resource($process)) {
            throw new RuntimeException('Failed to start the SSH2 audit child.');
        }
        fclose($pipes[0]);
        echo stream_get_contents($pipes[1]);
        echo stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);
        if ($status !== 0) {
            throw new RuntimeException("SSH2 audit child failed with status {$status}.");
        }
    } finally {
        foreach ([$library, $report] as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        rmdir($directory);
    }
}

/** These counters cover libssh2's allocator callbacks, including allocations outside Zend's heap. */
function ssh2t_native_counters(): array
{
    $report = file_get_contents(getenv('SWOOLE_SSH2_AUDIT_REPORT'));
    if (strlen($report) !== 48) {
        throw new RuntimeException('Invalid SSH2 audit report.');
    }
    $counts = unpack('Qlive/Qallocations/Qfrees/Qsessions/Qsession_frees/Qactive', $report);
    if ($counts['active'] !== 1) {
        throw new RuntimeException('The native SSH2 audit fixture was not loaded.');
    }
    return $counts;
}
