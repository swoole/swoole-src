--TEST--
swoole_client_coro: timeout of udp client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9502);
    $peer = null;
    $data = $socket->recvfrom($peer);
    echo "recvfrom client\n";
});

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $begin = time();
    $timeout_sec = 2;
    if (!$cli->connect('127.0.0.1', 9502, $timeout_sec)) {
        fail:
        echo "ERROR\n";
        return;
    }
    if (!$cli->send("hello")) {
        goto fail;
    }
    $ret = $cli->recv();
    $interval = time() - $begin;
    if ($ret !== false) {
        var_dump($ret);
    }
    if ($interval < $timeout_sec) {
        goto fail;
    }
    $cli->close();
    echo "TIMEOUT\n";
});
swoole_event::wait();
?>
--EXPECT--
recvfrom client
TIMEOUT
