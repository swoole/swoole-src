--TEST--
swoole_client_coro: connect with dns
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
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::assert($cli->connect('www.gov.cn', 80));
});

?>
--EXPECT--
