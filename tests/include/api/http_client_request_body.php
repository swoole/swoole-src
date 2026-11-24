<?php

use Swoole\Coroutine\Socket;

function http_client_body_listener(bool $ssl): Socket
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    if ($ssl) {
        Assert::true($listener->setProtocol([
            'open_ssl' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        ]));
    }
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    return $listener;
}

function http_client_body_headers(Socket $peer, string &$buffer): ?array
{
    while (($end = strpos($buffer, "\r\n\r\n")) === false) {
        $data = $peer->recv(4096, 5);
        Assert::notSame($data, false);
        if ($data === '') {
            Assert::same($buffer, '');
            return null;
        }
        $buffer .= $data;
    }
    $header = substr($buffer, 0, $end);
    $buffer = substr($buffer, $end + 4);
    Assert::same(preg_match('/\r\nContent-Length: ([0-9]+)\r?$/im', $header, $match), 1);
    Assert::same(preg_match('/\r\nTransfer-Encoding:/i', $header), 0);
    return ['header' => $header, 'length' => (int) $match[1]];
}

function http_client_body_digest(Socket $peer, string &$buffer, int $length): string
{
    $hash = hash_init('sha256');
    $remaining = $length;
    while ($remaining > 0) {
        if ($buffer === '') {
            $buffer = $peer->recv(min(65536, $remaining), 5);
            Assert::notSame($buffer, false);
            Assert::notSame($buffer, '');
        }
        $take = min($remaining, strlen($buffer));
        hash_update($hash, substr($buffer, 0, $take));
        $buffer = substr($buffer, $take);
        $remaining -= $take;
    }
    return hash_final($hash);
}

function http_client_body_reply(Socket $peer, string $body, int $status = 200, bool $close = false): void
{
    $connection = $close ? 'close' : 'keep-alive';
    $response = "HTTP/1.1 $status Status\r\nConnection: $connection\r\nContent-Length: " . strlen($body) . "\r\n\r\n$body";
    Assert::same($peer->sendAll($response), strlen($response));
}
