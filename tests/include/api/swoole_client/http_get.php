<?php

use Swoole\Client;

function client_http_v10_get(Client $client, string $host = 'httpbin.org', int $port = 80)
{
    Assert::assert($client->connect($host, $port, 10));
    $authority = $host . ($port === 80 ? '' : ":{$port}");
    Assert::assert($client->send("GET / HTTP/1.1\r\nHost: {$authority}\r\nConnection: close\r\n\r\n"));

    $resp = '';
    while (true) {
        $data = $client->recv();
        if ($data === '' || $data === false) {
            break;
        }
        $resp .= $data;
    }

    Assert::assert(str_starts_with($resp, 'HTTP/1.1 200 OK'));
    Assert::assert(str_contains($resp, 'https://github.com/requests/httpbin'));
}
