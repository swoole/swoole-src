<?php
go(function () {
    $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $ret = $sock->bind('127.0.0.1', 9601);
    var_dump($ret);
    assert($sock->listen(512));
    $conn = $sock->accept();

    $data = $conn->recv();
    var_dump($data);
    $json = json_decode($data, true);
    var_dump($json);
    $ret = $conn->send("world\n");
    echo "send res {$ret} \n";
    $conn->close();
});
