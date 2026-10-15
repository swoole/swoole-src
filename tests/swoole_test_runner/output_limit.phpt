--TEST--
PHPT runner: excessive output fails the test without abandoning parallel workers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('exec');
skip_if_function_not_exist('posix_kill');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);

$directory = sys_get_temp_dir() . '/swoole_runner_output_' . getmypid();
mkdir($directory, 0700);
$pidFile = $directory . '/pid';
$flood = <<<'PHPT'
    --TEST--
    runner output limit
    --FILE--
    <?php
    file_put_contents(%s, getmypid());
    $chunk = str_repeat('x', 65536);
    for ($i = 0; $i < 1100; $i++) {
        for ($offset = 0; $offset < strlen($chunk); $offset += $written) {
            $written = fwrite(STDOUT, substr($chunk, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Unable to write the output-limit fixture');
            }
        }
    }
    sleep(3);
    ?>
    --EXPECTF--
    %%A
    PHPT;
$healthy = <<<'PHPT'
    --TEST--
    runner healthy test
    --FILE--
    <?php echo "OK\n"; ?>
    --EXPECT--
    OK
    PHPT;
$timeout = <<<'PHPT'
    --TEST--
    runner timeout
    --FILE--
    <?php sleep(3); ?>
    --EXPECTF--
    %A
    PHPT;

try {
    file_put_contents($directory . '/flood.phpt', sprintf($flood, var_export($pidFile, true)));
    file_put_contents($directory . '/healthy.phpt', $healthy);
    file_put_contents($directory . '/timeout.phpt', $timeout);
    // Workers load this smaller php.ini but must keep the runner's 128M runtime memory limit.
    $iniFile = $directory . '/php.ini';
    file_put_contents($iniFile, "memory_limit=32M\n");
    $runner = 'PHPRC=' . escapeshellarg($iniFile) . ' REPORT_EXIT_STATUS=1 NO_INTERACTION=1 '
        . escapeshellarg(PHP_BINARY) . ' -n -d memory_limit=128M '
        . escapeshellarg(TESTS_ROOT_PATH . '/run-tests')
        . ' -n';
    $command = $runner . ' -j2 --set-timeout 5 ' . escapeshellarg($directory . '/flood.phpt')
        . ' ' . escapeshellarg($directory . '/healthy.phpt') . ' 2>&1';
    exec($command, $lines, $exitCode);
    $output = preg_replace('/\x1b\[[0-9;]*m/', '', implode("\n", $lines));

    Assert::notSame($exitCode, 0);
    Assert::contains($output, 'ERROR: process output exceeded the maximum size', $output);
    // The broad EXPECTF must not turn a terminated test into a pass.
    Assert::contains($output, '[FAIL] runner output limit');
    Assert::contains($output, '[PASS] runner healthy test');
    Assert::contains($output, 'FAILED TEST SUMMARY');
    Assert::notContains($output, 'died unexpectedly');
    Assert::false(posix_kill((int) file_get_contents($pidFile), 0));

    // Also enforce the limit when the producer exits without keeping its output pipe open.
    $exitedFlood = str_replace('sleep(3);', '', sprintf($flood, var_export($pidFile, true)));
    file_put_contents($directory . '/exited.phpt', $exitedFlood);
    exec($runner . ' --show-out --set-timeout 5 ' . escapeshellarg($directory . '/exited.phpt') . ' 2>&1', $exitedLines, $exitCode);
    $output = preg_replace('/\x1b\[[0-9;]*m/', '', implode("\n", $exitedLines));
    Assert::notSame($exitCode, 0);
    Assert::contains($output, 'ERROR: process output exceeded the maximum size', $output);
    Assert::contains($output, '[FAIL] runner output limit');

    exec($runner . ' --show-out --set-timeout 1 ' . escapeshellarg($directory . '/timeout.phpt') . ' 2>&1', $timeoutLines, $exitCode);
    $output = preg_replace('/\x1b\[[0-9;]*m/', '', implode("\n", $timeoutLines));
    Assert::notSame($exitCode, 0);
    Assert::contains($output, 'ERROR: process timed out after 1 seconds');
    Assert::contains($output, '[FAIL] runner timeout');
} finally {
    foreach (glob($directory . '/*') as $file) {
        unlink($file);
    }
    rmdir($directory);
}

echo "DONE\n";
?>
--EXPECT--
DONE
