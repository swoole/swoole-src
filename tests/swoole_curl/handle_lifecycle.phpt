--TEST--
swoole_curl: native and coroutine handles retain their own lifecycle handlers (#6443)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('curl is required', !extension_loaded('curl'));
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip_if_function_not_exist('proc_open');
?>
--INI--
error_reporting=24575
--FILE--
<?php
// Check the exit code as well as output: a shutdown crash can follow the final echo.
$modes = [
    'native-shutdown', 'native-attached-shutdown', 'native-unset', 'native-gc',
    'native-clone', 'native-hook-enabled', 'native-after-co', 'native-in-co', 'native-marker',
    'co-escape', 'co-hook-disabled', 'co-gc', 'co-clone', 'co-marker', 'co-add-native',
];
foreach ($modes as $mode) {
    $outputFile = tempnam(sys_get_temp_dir(), 'swoole-curl-lifecycle-');
    $command = (PHP_OS_FAMILY === 'Windows' ? '' : 'exec ') . escapeshellarg(PHP_BINARY)
        . ' ' . getenv('TEST_PHP_EXTRA_ARGS') . ' '
        . escapeshellarg(__DIR__ . '/handle_lifecycle.inc') . ' ' . escapeshellarg($mode);
    $process = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['file', $outputFile, 'w'],
        2 => ['redirect', 1],
    ], $pipes);
    if (!is_resource($process)) {
        unlink($outputFile);
        throw new RuntimeException('Cannot start lifecycle child');
    }
    fclose($pipes[0]);
    try {
        $deadline = microtime(true) + 10;
        do {
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        if ($status['running']) {
            proc_terminate($process);
            throw new RuntimeException($mode . ': timed out');
        }
        $exit = proc_close($process);
        $process = null;
        $exit = $status['exitcode'] !== -1 ? $status['exitcode'] : $exit;
        $output = str_replace("\r\n", "\n", file_get_contents($outputFile));
        if ($exit !== 0 || $output !== "DONE\n") {
            throw new RuntimeException($mode . ': ' . var_export([$exit, $output], true));
        }
        echo $mode, ": OK\n";
    } finally {
        if (is_resource($process)) {
            proc_close($process);
        }
        unlink($outputFile);
    }
}
?>
--EXPECT--
native-shutdown: OK
native-attached-shutdown: OK
native-unset: OK
native-gc: OK
native-clone: OK
native-hook-enabled: OK
native-after-co: OK
native-in-co: OK
native-marker: OK
co-escape: OK
co-hook-disabled: OK
co-gc: OK
co-clone: OK
co-marker: OK
co-add-native: OK
