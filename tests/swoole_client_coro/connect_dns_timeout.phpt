--TEST--
swoole_client_coro: connect dns timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set(['socket_dns_timeout' => 0.005]);

Co\run(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::assert(!@$cli->connect('xxx.66xx.6855.xxx.xx'.rand(1000, 9999) . time(), 80));
    Assert::same($cli->errCode, SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
});
?>
--EXPECT--
