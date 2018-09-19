<?php

echo "start \n";
go(function ()  {
    $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $ret = $conn->connect('127.0.0.1', 9601);
    echo "connect ret:".var_export($ret,1)." error:".var_export($conn->errCode,1)."\n";
    $ret = $conn->send(json_encode(['data' => 'hello']));
    echo "send ret:".var_export($ret,1)."\n";
    echo $conn->recv();
});
echo "end \n";
