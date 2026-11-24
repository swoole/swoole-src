<?php
// Coroutine file I/O: writeFile() and readFile() yield while the disk works.
// Run: php examples/coroutine/system_file_io.php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

$tmp = __DIR__ . '/system_file_io.tmp';
register_shutdown_function(function () use ($tmp) {
    if (is_file($tmp)) {
        @unlink($tmp);
    }
});

run(function () use ($tmp) {
    System::writeFile($tmp, 'hello coroutine');
    echo System::readFile($tmp), PHP_EOL;
});
