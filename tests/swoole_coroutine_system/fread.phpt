--TEST--
swoole_coroutine_system: fread
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Event;

define('FILE', __DIR__ . '/test.txt');

file_put_contents(FILE, '1234567890');

go(function () {
    $fp = fopen(FILE, 'r');
    Assert::eq(System::fread($fp, 4), '1234');
    Assert::eq(System::fread($fp, 6), '567890');
    Assert::eq(System::fread($fp), '');
    fclose($fp);
});

Event::wait();
unlink(FILE);
?>
--EXPECT--
