<?php
namespace Swoole\Coroutine {
    class Socket {
        public function __construct(int $domain, int $type, int $protocol) {}
        public function bind(string $address,int $port = 0): bool {}
        public function listen(int $backlog = 512): bool {}
        public function accept(float $timeout = 0): Socket|bool {}
        public function connect(string $host, int $port = 0, float $timeout = 0): bool {}
        public function checkLiveness(): bool {}
        public function peek(int $length = 65536): string|bool {}
        public function recv(int $length = 65536, float $timeout = 0): string|bool {}
        public function send(string $data, float $timeout = 0): int|bool {}
        public function readVector(array $io_vector, float $timeout = 0): bool|array {}
        public function readVectorAll(array $io_vector, float $timeout = 0): bool|array {}
        public function writeVector(array $io_vector, float $timeout = 0): bool|int {}
        public function writeVectorAll(array $io_vector, float $timeout = 0): bool|int {}
        public function sendFile(string $file, int $offset = 0, int $length = 0): bool {}
        public function recvAll(int $length = 65536, float $timeout = 0): bool|string {}
        public function sendAll(string $data, float $timeout = 0): int|bool {}
        public function recvPacket(float $timeout = 0):bool|string {}
        public function recvLine(int $length = 65535, float $timeout = 0): string|bool {}
        public function recvWithBuffer(int $length = 65535, float $timeout = 0): string|bool {}
        public function recvfrom(array &$peername, float $timeout = 0): string|bool {}
        public function sendto(string $addr, int $port, string $data): int|bool {}
        public function getOption(int $level, int $opt_name): mixed {}
        public function setOption(int $level, int $opt_name, mixed $opt_value):bool {}
        public function setProtocol(array $settings): bool {}
        public function sslHandshake(): bool {}
        public function shutdown(int $how = Socket::SHUT_RDWR): bool {}
        public function close(): bool {}
        public function cancel(int $event = SWOOLE_EVENT_READ): bool {}
        public function getsockname(): bool|array {}
        public function getpeername(): bool|array {}
        public function isClosed(): bool {}
    }
}
