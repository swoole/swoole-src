--TEST--
swoole_coroutine: dns lookup cache separates address families
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    Assert::eq(System::dnsLookup('localhost', 1, AF_INET), '127.0.0.1');
    Assert::assert(filter_var(System::dnsLookup('localhost', 1, AF_INET6), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false);
});
?>
--EXPECT--
