--TEST--
swoole_coroutine: async dns lookup [3]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $host = swoole_async_dns_lookup_coro('www.' . uniqid() . '.' . uniqid(), 15);
    Assert::eq($host, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
});
swoole_event_wait();
?>
--EXPECT--
