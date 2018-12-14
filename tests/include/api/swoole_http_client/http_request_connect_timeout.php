<?php
$httpClient = new swoole_http_client("11.11.11.11", 9000);
$httpClient->set(['timeout' => 1]);

$httpClient->get("/", function ($client)
{
    assert($client->errCode == SOCKET_ETIMEDOUT);
    assert($client->statusCode == -1);
    assert(!$client->body);
});
