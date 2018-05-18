<?php
//Server
go(function () {
    $socket = new Co\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9601);
    while (true) {
        $peer = null;
        $data = $socket->recvfrom($peer);
        echo "[Server] recvfrom[{$peer['address']}:{$peer['port']}] : $data\n";
        $socket->sendto($peer['address'], $peer['port'], "Swoole: $data");
    }
});

//Client
go(function () {
    $socket = new  Co\Socket(AF_INET, SOCK_DGRAM, 0);
    $i = 0;
    while (true)
    {
        $socket->sendto('127.0.0.1', 9601, "HELO-" . $i++);
        $peer = null;
        $data = $socket->recvfrom($peer);
        echo "[Client] recvfrom[{$peer['address']}:{$peer['port']}] : $data\n";
        co::sleep(1);
    }
});
