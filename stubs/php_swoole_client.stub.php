<?php
namespace Swoole {
	class Client {
		public function __construct(int $type, bool $async = SWOOLE_SOCK_SYNC, string $id = '') {}
		public function __destruct() {}
		public function set(array $settings): bool {}
		public function connect(string $host, int $port = 0, float $timeout = 0.5, int $sock_flag = 0): bool {}
		public function recv(int $size = 65536, int $flag = 0): string|false {}
		public function send(string $data, int $flag = 0): false|int {}
		public function sendfile(string $filename, int $offset = 0, int $length = 0): bool {}
		public function sendto(string $ip, int $port, string $data): bool {}
		#ifdef SW_USE_OPENSSL
		public function enableSSL(): bool {}
		public function getPeerCert(): string|bool {}
		public function verifyPeerCert(): bool {}
		#endif
		public function isConnected(): bool {}
		public function getsockname(): array|false {}
		public function getpeername(): array|false {}
		public function close(bool $force = false): bool {}
		public function shutdown(int $how): bool {}
		#ifdef SWOOLE_SOCKETS_SUPPORT
		public function getSocket(): \Socket|false {}
		#endif
	}
}
