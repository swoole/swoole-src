--TEST--
swoole_socket_coro: getpeername
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;

Co\run(
    function () {
        $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        $conn->connect('www.baidu.com', 80);
        $info = $conn->getpeername();
        Assert::eq($info['address'], System::gethostbyname('www.baidu.com'));
        Assert::eq($info['port'], 80);
    }
);
?>
--EXPECT--
