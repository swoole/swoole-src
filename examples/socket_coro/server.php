<?php
$socket = new Co\Socket(AF_INET, SOCK_STREAM, 0);
$socket->bind('127.0.0.1', 9601);
$socket->listen(128);

go(function () use ($socket) {
    while(true) {
        $client = $socket->accept();
        go(function () use ($client) {
            while(true) {
                $data = $client->recv();
                if (empty($data)) {
                    $client->close();
                    break;
                }
                var_dump($client->getsockname());
                var_dump($client->getpeername());
                $client->send("Server: $data");
            }
        });
    }
});
