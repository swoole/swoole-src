<?php
require_once __DIR__ . '/http2_raw_client.php';

function http2_trailer_integer(int $value, int $prefix, int $bits = 0): string
{
    $limit = (1 << $prefix) - 1;
    if ($value < $limit) {
        return chr($bits | $value);
    }
    $data = chr($bits | $limit);
    for ($value -= $limit; $value >= 128; $value = intdiv($value, 128)) {
        $data .= chr(($value & 127) | 128);
    }
    return $data . chr($value);
}

function http2_trailer_field(string $name, string $value, bool $indexed = false): string
{
    return ($indexed ? "\x40" : "\x00")
        . http2_trailer_integer(strlen($name), 7) . $name
        . http2_trailer_integer(strlen($value), 7) . $value;
}

function http2_trailer_headers(string $path = '/', string $method = 'POST'): string
{
    return http2_trailer_field(':method', $method) . "\x86"
        . http2_trailer_field(':path', $path) . "\x01\x09localhost";
}

function http2_trailer_connect(int $port)
{
    $socket = stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $error, 2);
    if ($socket === false) {
        throw new RuntimeException($error);
    }
    stream_set_timeout($socket, 2);
    $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(4, 0, 0);
    Assert::same(fwrite($socket, $preface), strlen($preface));
    return $socket;
}

function http2_trailer_send($socket, int $type, int $flags, int $id, string $payload = ''): void
{
    $frame = http2_test_frame($type, $flags, $id, $payload);
    Assert::same(fwrite($socket, $frame), strlen($frame));
}

function http2_trailer_response($socket, int $id): array
{
    $body = '';
    $headers = '';
    while (($frame = http2_test_read_frame($socket)) !== false) {
        if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
            http2_trailer_send($socket, 4, 1, 0);
        }
        if ($frame['streamId'] !== $id) {
            continue;
        }
        if ($frame['type'] === 3) {
            return ['reset' => unpack('N', $frame['payload'])[1]];
        }
        if ($frame['type'] === 1 || $frame['type'] === 9) {
            $headers .= $frame['payload'];
        } elseif ($frame['type'] === 0) {
            $body .= $frame['payload'];
        }
        if (($frame['type'] === 0 || $frame['type'] === 1) && ($frame['flags'] & 1)) {
            return ['headers' => $headers, 'body' => $body];
        }
    }
    throw new RuntimeException('Incomplete HTTP/2 response');
}

function http2_trailer_server(ProcessManager $pm, $mode, callable $handler, array $settings = []): void
{
    if ($mode === 'coroutine') {
        Swoole\Coroutine::set($settings + ['log_file' => '/dev/null']);
        Swoole\Coroutine\run(function () use ($pm, $handler, $settings) {
            $server = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort(), false);
            $server->set($settings);
            $server->handle('/', $handler);
            $pm->wakeup();
            $server->start();
        });
        return;
    }
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
    $server->set($settings + [
        'worker_num' => 1,
        'reactor_num' => 1,
        'open_http2_protocol' => true,
        'http_compression' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', $handler);
    $server->start();
}
