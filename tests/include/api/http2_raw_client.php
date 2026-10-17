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

function http2_test_open_request(int $port, string $path)
{
    $client = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 2);
    if ($client === false) {
        throw new RuntimeException("connect failed: {$errstr} [{$errno}]");
    }
    stream_set_timeout($client, 2);

    $settings = http2_test_frame(4, 0, 0, pack('nN', 4, 1));
    $headers = "\x82\x86\x04" . chr(strlen($path)) . $path . "\x01\x09localhost";
    $request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        . $settings
        . http2_test_frame(1, 5, 1, $headers);
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
