<?php

/** Run a termination regression in its own PHP process, with a deadline and process-group cleanup. */
function run_unwind_exit_php(string $code, array $arguments = [], float $timeout = 10): array
{
    $directory = sys_get_temp_dir() . '/swoole-unwind-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $script = $directory . '/child.php';
    file_put_contents($script, "<?php\nif (function_exists('posix_setsid') && posix_setsid() >= 0) { file_put_contents("
        . var_export($directory . '/group', true) . ", (string) getmypid()); }\n" . $code);
    $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' ' . getenv('TEST_PHP_EXTRA_ARGS')
        . ' -d memory_limit=32M -d display_errors=stderr ' . escapeshellarg($script);
    foreach (array_merge([$directory], $arguments) as $argument) {
        $command .= ' ' . escapeshellarg((string) $argument);
    }
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the regression child');
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = $stderr = '';
    $deadline = microtime(true) + $timeout;
    $status = proc_get_status($process);
    try {
        while ($status['running'] && microtime(true) < $deadline) {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            usleep(10000);
            $status = proc_get_status($process);
        }
        if ($status['running']) {
            throw new RuntimeException("Termination regression timed out\n$stdout\n$stderr");
        }
        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
    } finally {
        // All descendants inherit this test child's session; never signal the test runner's group.
        if (function_exists('posix_kill') && @file_get_contents($directory . '/group') === (string) $status['pid']) {
            posix_kill(-$status['pid'], SIGKILL);
        } elseif ($status['running']) {
            proc_terminate($process, 9);
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);
        foreach (glob($directory . '/*') as $file) {
            unlink($file);
        }
        rmdir($directory);
    }
    return [$status['exitcode'] >= 0 ? $status['exitcode'] : $exit, $stdout, $stderr];
}

function assert_unwind_exit(array $result, int $exit, string $stdout): void
{
    if ($result[0] !== $exit || $result[1] !== $stdout) {
        throw new RuntimeException('Unexpected termination result: ' . var_export($result, true));
    }
}
