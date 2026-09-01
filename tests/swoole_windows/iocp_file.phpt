--TEST--
swoole_windows: iocp file lifecycle
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

$filename = sys_get_temp_dir() . '/swoole-iocp-file-' . getmypid() . '.tmp';
$first = str_repeat('iocp-read-write-', 1024);
$second = "append-data\n";

Runtime::enableCoroutine(SWOOLE_HOOK_FILE);
try {
    run(function () use ($filename, $first, $second) {
        Assert::same(file_put_contents($filename, $first), strlen($first));
        Assert::same(file_put_contents($filename, $second, FILE_APPEND), strlen($second));
        Assert::same(file_get_contents($filename), $first . $second);
        Assert::same(System::readFile($filename), $first . $second);

        $stream = fopen($filename, 'r+b');
        Assert::assert(is_resource($stream));
        Assert::same(fseek($stream, strlen($first)), 0);
        Assert::same(fread($stream, strlen($second)), $second);
        Assert::same(fseek($stream, 5), 0);
        Assert::same(fwrite($stream, 'IOCP'), 4);
        fclose($stream);

        Assert::same(substr(file_get_contents($filename), 5, 4), 'IOCP');
        $stats = Coroutine::stats();
        Assert::same($stats['iocp_blocking_task_num'], 0);
        Assert::same($stats['iocp_task_num'], 0);
    });
} finally {
    Runtime::enableCoroutine(false);
    @unlink($filename);
}

echo "DONE\n";
?>
--EXPECT--
DONE
