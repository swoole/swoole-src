--TEST--
swoole_coroutine_system: fwrite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Event;

const FILE = __DIR__ . '/test.txt';
const N = 1024;

go(function () {
    $fp = fopen(FILE, 'w');
    Assert::assert(System::fwrite($fp, '1234'));
    Assert::assert(System::fwrite($fp, '567890'));
    Assert::eq(file_get_contents(FILE), '1234567890');
    ftruncate($fp, 0);
    fclose($fp);

    $fp = fopen(FILE, 'w');
    $data = str_repeat('A', N);
    Assert::assert(System::fwrite($fp, $data));
    go(function () use (&$data, $fp) {
        $data = str_repeat('B', 65536);
    });
    Assert::eq(file_get_contents(FILE), str_repeat('A', N));
});

Event::wait();
unlink(FILE);
?>
--EXPECT--
