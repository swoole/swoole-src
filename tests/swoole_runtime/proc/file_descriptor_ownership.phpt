--TEST--
swoole_runtime/proc: preserve file descriptor ownership
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

Co\run(static function (): void {
    $descriptorSpec = [
        0 => ['file', '/dev/null', 'r'],
        1 => ['file', '/dev/null', 'w'],
        2 => ['file', '/dev/null', 'w'],
    ];

    for ($i = 0; $i < 3; $i++) {
        $process = proc_open([PHP_BINARY, '-n', '-r', 'exit(0);'], $descriptorSpec, $pipes);

        Assert::true(is_resource($process));
        Assert::same(proc_close($process), 0);
    }
});

echo "Done\n";
?>
--EXPECT--
Done
