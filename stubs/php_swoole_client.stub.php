<?php
/**
 * @strict-properties
 * @not-serializable
 */
namespace Swoole {
	class Client {
		public function __construct(int $type, int $async = SWOOLE_SOCK_SYNC, string $id = '') {}
		public function __destruct() {}
		public function set(array $settings): bool {}
		public function connect(string $host, int $port, float $timeout = 0.5, int $sock_flag = 0): bool {}
		public function recv(int $size = 65536, int $flag = 0): string|bool {}
		public function send(string $data, int $flag = 0): bool|int {}
		public function sendfile(string $filename, int $offset = 0, int $length = 0): bool {}
		public function sendto(string $ip, int $port, string $data): bool {}
		public function enableSSL(): bool {}
		public function getPeerCert(): string|bool {}
		public function verifyPeerCert(): bool {}
		public function isConnected(): bool {}
		public function getsockname(): array|bool {}
		public function getpeername(): array|bool {}
		public function close(bool $force = false): bool {}
		public function shutdown(int $how): bool {}
		public function getSocket(): bool {}
	}
}
