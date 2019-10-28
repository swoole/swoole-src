--TEST--
swoole_coroutine: swoole_async_dns_lookup_coro
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $host = swoole_async_dns_lookup_coro('www.baidu.com');
    Assert::assert(filter_var($host, FILTER_VALIDATE_IP) !== false);
});
swoole_event_wait();
?>
--EXPECT--
