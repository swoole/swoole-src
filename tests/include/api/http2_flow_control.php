<?php
/**
 * This file is part of Swoole.
 *
 * @link https://www.swoole.com
 * @contact team@swoole.com
 * @license https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);

require_once __DIR__ . '/http2_raw_client.php';

final class Http2FlowPeer
{
    public $socket;
    public array $bodies = [];
    public array $ended = [];
    public int $total = 0;
    private int $ping = 0;

    public function __construct(int $port, int $window = 65535, bool $tls = false)
    {
        $context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        $this->socket = stream_socket_client(($tls ? 'tls' : 'tcp') . "://127.0.0.1:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $context);
        Assert::notEmpty($this->socket);
        stream_set_timeout($this->socket, 2);
        $this->sendBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        $this->settings($window);
    }

    public function sendBytes(string $data): void
    {
        while ($data !== '') {
            $n = fwrite($this->socket, $data);
            if ($n === false || $n === 0) {
                throw new RuntimeException('Failed to write HTTP/2 frame');
            }
            $data = substr($data, $n);
        }
    }

    public function send(int $type, int $flags, int $id, string $payload = ''): void
    {
        $this->sendBytes(http2_test_frame($type, $flags, $id, $payload));
    }

    public function settings(int $window): void
    {
        $this->send(4, 0, 0, pack('nN', 4, $window));
    }

    public function request(int $id, string $path, bool $end = true): void
    {
        $frame = http2_test_request_headers($id, $path);
        if (!$end) {
            $frame[4] = chr(4);
        }
        $this->sendBytes($frame);
    }

    public function update(int $id, int $increment): void
    {
        $this->send(8, 0, $id, pack('N', $increment));
    }

    public function read(): array
    {
        $frame = http2_test_read_frame($this->socket);
        if ($frame === false) {
            throw new RuntimeException('Failed to read frame: ' . json_encode([
                'bytes' => array_map('strlen', $this->bodies), 'ended' => $this->ended,
                'transport' => stream_get_meta_data($this->socket),
            ]));
        }
        if ($frame['type'] === 4 && !($frame['flags'] & 1)) {
            $this->send(4, 1, 0);
        }
        if ($frame['type'] === 8) {
            Assert::greaterThan(unpack('N', $frame['payload'])[1] & 0x7fffffff, 0);
        }
        if ($frame['type'] === 0) {
            $id = $frame['streamId'];
            $this->bodies[$id] = ($this->bodies[$id] ?? '') . $frame['payload'];
            $this->total += strlen($frame['payload']);
        }
        if (in_array($frame['type'], [0, 1], true) && ($frame['flags'] & 1)) {
            $this->ended[$frame['streamId']] = true;
        }
        return $frame;
    }

    public function barrier(): void
    {
        $token = pack('J', ++$this->ping);
        $this->send(6, 0, 0, $token);
        do {
            $frame = $this->read();
        } while ($frame['type'] !== 6 || $frame['payload'] !== $token);
        Assert::same($frame['flags'], 1);
    }

    public function bytes(int $id, int $length): void
    {
        while (strlen($this->bodies[$id] ?? '') < $length) {
            $this->read();
        }
        Assert::same(strlen($this->bodies[$id] ?? ''), $length);
    }

    public function closed(): void
    {
        while (@http2_test_read_frame($this->socket) !== false) {
        }
        Assert::true(feof($this->socket));
    }

    public function close(): void
    {
        fclose($this->socket);
    }
}

function http2_flow_server(ProcessManager $pm, $mode, Closure $handler, bool $tls = false, array $settings = []): void
{
    $settings += [
        'open_http2_protocol' => true,
        'http_compression' => false,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ];
    if ($mode === 'coroutine') {
        Swoole\Coroutine\run(function () use ($pm, $handler, $tls, $settings) {
            $server = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort(), $tls);
            $server->set($settings);
            $server->handle('/', $handler);
            $pm->wakeup();
            $server->start();
        });
    } else {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode, SWOOLE_SOCK_TCP | ($tls ? SWOOLE_SSL : 0));
        $server->set($settings + ['worker_num' => 1, 'log_file' => '/dev/null']);
        $server->on('WorkerStart', fn () => $pm->wakeup());
        $server->on('Request', fn ($request, $response) => $handler($request, $response, $server));
        $server->start();
    }
}
