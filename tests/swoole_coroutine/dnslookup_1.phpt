--TEST--
swoole_coroutine: swoole_async_dns_lookup_coro
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip online test");
}
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
