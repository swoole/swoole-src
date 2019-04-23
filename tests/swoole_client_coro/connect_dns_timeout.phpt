--TEST--
swoole_client_coro: connect dns timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::assert(!@$cli->connect('xxx.66xx.6855.xxx.xx' . time(), 80, 0.001));
    Assert::eq($cli->errCode, SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
});

?>
--EXPECT--
