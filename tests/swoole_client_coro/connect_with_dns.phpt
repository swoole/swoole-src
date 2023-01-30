--TEST--
swoole_client_coro: connect with dns
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::true($cli->connect('www.qq.com', 80));
});

?>
--EXPECT--
