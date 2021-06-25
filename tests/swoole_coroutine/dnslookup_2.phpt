--TEST--
swoole_coroutine: async dns lookup timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    $host = Swoole\Coroutine::dnsLookup('www.' . uniqid() . '.' . uniqid(), 0.5);
    Assert::eq($host, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
});
?>
--EXPECT--
