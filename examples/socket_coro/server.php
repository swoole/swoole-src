<?php
$socket = new Co\Socket(AF_INET, SOCK_STREAM, 0);
$socket->bind('127.0.0.1', 9601);
$socket->listen(128);

go(function () use ($socket) {
    while(true) {
        echo "Accept: \n";
        $client = $socket->accept();

        echo "New Coroutine: \n";
        go(function () use ($client) {
            while(true) {
                echo "Client Recv: \n";
                $data = $client->recv();
                if (empty($data)) {
                    $client->close();
                    break;
                }
                var_dump($client->getsockname());
                var_dump($client->getpeername());
                echo "Client Send: \n";
                $client->send("Server: $data");
            }
        });
    }
});
