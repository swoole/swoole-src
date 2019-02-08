--TEST--
swoole_client_coro: connect with dns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    assert($cli->connect('www.gov.cn', 80));
});

?>
--EXPECT--
