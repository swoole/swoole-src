<?php
namespace Swoole\Coroutine {
    class Client {
        public function __construct(int $type) {}
        public function __destruct() {}
        public function set(array $settings): bool {}
        public function connect(string $host, int $port = 0, float $timeout = 0, int $sock_flag = 0): bool {}
        public function recv(float $timeout = 0): string|false {}
        public function peek(int $length = 65535): string|false {}
        public function send(string $data, float $timeout = 0): int|false {}
        public function sendfile(string $filename, int $offset = 0, int $length = 0): bool {}
        public function sendto(string $address, int $port, string $data): bool {}
        public function recvfrom(int $length, mixed &$address, mixed &$port = 0): false|string {}
        public function enableSSL(): bool {}
        public function getPeerCert(): false|string {}
        public function verifyPeerCert(bool $allow_self_signed = false): bool {}
        public function exportSocket(): \Swoole\Coroutine\Socket|false {}
        public function isConnected(): bool {}
        public function getsockname(): array|false {}
        public function getpeername(): array|false {}
        public function close(): bool {}
    }
}
