<?php

$socket = new Co\Socket(AF_INET, SOCK_STREAM, 0);
$socket->bind("0.0.0.0", 9501);
$socket->listen();

go(function() use($socket) {
    while (1) {
        go(function() use ($socket) {
            $client = $socket->accept(-1);
            while (true) {
                $data = $client->recv();
                if (empty($data)) {
                    $client->close();
                    break;
                }
                //do business
                $client->send("server" . $data);
            }
        });
    }
});
