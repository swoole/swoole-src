--TEST--
swoole_coroutine: dnslookup query hosts
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    Assert::eq(System::dnsLookup('localhost', 3, AF_INET), '127.0.0.1');
});

?>
--EXPECT--
