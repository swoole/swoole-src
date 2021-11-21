<?php
namespace Swoole\Coroutine\Http2 {
    class Client {
        public function __construct(string $host, int $port = 80, bool $open_ssl = false) {}
        public function __destruct() {}
        public function set(array $settings): bool {}
        public function connect(): bool {}
        public function stats(string $key): array|bool {}
        public function isStreamExist(int $stream_id): bool {}
        public function send(\Swoole\Http2\Request $request): int|bool {}
        public function write(int $stream_id, mixed $data, bool $end_stream = false): bool {}
        public function recv(float $timeout = 0): \Swoole\Http2\Response|bool {}
        public function read(): \Swoole\Http2\Response|bool {}
        public function ping(): bool {}
        public function goaway(int $error_code = SWOOLE_HTTP2_ERROR_NO_ERROR, string $debug_data = ''): bool {}
        public function close(): bool {}
    }
}
