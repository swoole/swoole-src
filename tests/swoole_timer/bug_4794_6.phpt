--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;

Co\run(
    function () {
        $conn = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $conn->connect('www.baidu.com', 80);
        $info = $conn->getpeername();
        Assert::eq($info['host'], System::gethostbyname('www.baidu.com'), 'AF_INET', 0.0001);
        Assert::eq($info['port'], 80);
    }
);
?>
--EXPECT--
