<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
require "websocket_client.php";

function send_large_request_data($host, $port)
{
    $client = new WebSocketClient($host, $port);
    if (!$client->connect())
    {
        echo "send failed, errCode={$client->errCode}\n";
        return false;
    }

    $data = str_repeat("data", 40000);
    for ($i = 0; $i < 100; $i++)
    {
        if (!$client->send($data))
        {
            echo "send failed, errCode={$client->errCode}\n";
            return false;
        }
        $response = $client->recv();
        Assert::same($response, "SUCCESS", "response failed");
    }
    return true;
}
