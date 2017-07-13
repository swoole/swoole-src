<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
require "websocket_client.php";

function send_large_request_data($host, $port)
{
    $client = new WebSocketClient($host, $port);
    $client->connect();

    $data = str_repeat("data", 40000);
    for ($i = 0; $i < 100; $i++)
    {
        $client->send($data);
        $response = $client->recv();
        assert($response == "SUCCESS", "response failed");
    }

}
