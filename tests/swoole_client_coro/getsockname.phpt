--TEST--
swoole_client_coro: getsockname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(
    function () {
        $conn = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $conn->connect('www.baidu.com', 80);
        $info = $conn->getsockname();
        Assert::assert(filter_var($info['host'], FILTER_VALIDATE_IP));
        Assert::greaterThan($info['port'], 0);
    }
);
?>
--EXPECT--
