--TEST--
swoole_coroutine: swoole_async_dns_lookup_coro
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $host = swoole_async_dns_lookup_coro('www.baidu.com');
    assert(filter_var($host, FILTER_VALIDATE_IP) !== false);
});
swoole_event_wait();
?>
--EXPECT--
