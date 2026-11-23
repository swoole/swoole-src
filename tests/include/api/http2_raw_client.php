<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);

function http2_test_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId)
        . $payload;
}

function http2_test_read_exact($client, int $length)
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($client, $length - strlen($data));
        if ($chunk === false || $chunk === '') {
            return false;
        }
        $data .= $chunk;
    }
    return $data;
}

function http2_test_read_frame($client)
{
    $header = http2_test_read_exact($client, 9);
    if ($header === false) {
        return false;
    }
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $payload = $length === 0 ? '' : http2_test_read_exact($client, $length);
    if ($payload === false) {
        return false;
    }
    return [
        'type' => ord($header[3]),
        'flags' => ord($header[4]),
        'streamId' => unpack('N', substr($header, 5, 4))[1] & 0x7FFFFFFF,
        'payload' => $payload,
    ];
}

function http2_test_request_headers(int $streamId, string $path): string
{
    $headers = "\x82\x86\x04" . chr(strlen($path)) . $path . "\x01\x09localhost";
    return http2_test_frame(1, 5, $streamId, $headers);
}

// Fill transport queues without spending HTTP/2 credit. The child only yields when Server::send()
// waits for output space. Cancel that pending send before the caller starts the operation under test.
function http2_test_fill_send_buffer(Swoole\Http\Server $server, int $fd): void
{
    $filler = Swoole\Coroutine::create(function () use ($server, $fd) {
        $extension = http2_test_frame(15, 0, 0, str_repeat('P', 16384));
        for ($i = 0; $i < 4096 && $server->send($fd, $extension); ++$i) {
        }
    });
    Assert::true(Swoole\Coroutine::cancel($filler));
}

function http2_test_open_request(int $port, string $path, int $windowSize = 1, int $connectionWindow = 65535, int $receiveBuffer = 0)
{
    $client = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 2);
    if ($client === false) {
        throw new RuntimeException("connect failed: {$errstr} [{$errno}]");
    }
    stream_set_timeout($client, 2);
    if ($receiveBuffer > 0) {
        Assert::true(socket_set_option(socket_import_stream($client), SOL_SOCKET, SO_RCVBUF, $receiveBuffer));
    }

    $settings = http2_test_frame(4, 0, 0, pack('nN', 4, $windowSize));
    $connection = $connectionWindow > 65535 ? http2_test_frame(8, 0, 0, pack('N', $connectionWindow - 65535)) : '';
    $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        . $settings . $connection
        . http2_test_request_headers(1, $path);
    Assert::same(fwrite($client, $request), strlen($request));
    return $client;
}

function http2_test_wait_for_frame($client, int $type, int $flags = -1): array
{
    while (true) {
        $received = http2_test_read_frame($client);
        if ($received === false) {
            throw new RuntimeException('failed to read HTTP/2 frame');
        }
        if ($received['type'] === 4 && ($received['flags'] & 1) === 0) {
            fwrite($client, http2_test_frame(4, 1, 0));
        }
        if ($received['type'] === $type && ($flags < 0 || $received['flags'] === $flags)) {
            return $received;
        }
    }
}
