--TEST--
swoole_coroutine: async dns lookup [5]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    $ip = System::dnsLookup('localhost');
    Assert::eq($ip, '127.0.0.1');
});
?>
--EXPECT--
