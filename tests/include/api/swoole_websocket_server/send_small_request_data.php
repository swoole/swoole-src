<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
require "websocket_client.php";

function send_small_request_data($host, $port)
{
    $client = new WebSocketClient($host, $port);
    $client->connect();

    $data = "";
    for ($i = 0; $i < 100; $i++)
    {
        $client->send($data);
        $response = $client->recv();
        assert($response == "SUCCESS", "response failed");
    }
}