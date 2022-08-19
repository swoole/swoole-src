--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    $host = Swoole\Coroutine::dnsLookup('www.' . uniqid() . '.' . uniqid(), 0.005);
    Assert::eq($host, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
});
?>
--EXPECT--
