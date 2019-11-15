--TEST--
swoole_coroutine_system: fwrite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Event;

define('FILE', __DIR__ . '/test.txt');

go(function () {
    $fp = fopen(FILE, 'w');
    Assert::assert(System::fwrite($fp, '1234'));
    Assert::assert(System::fwrite($fp, '567890'));
    Assert::eq(file_get_contents(FILE), '1234567890');
});

Event::wait();
unlink(FILE);
?>
--EXPECT--
