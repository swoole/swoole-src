<?php
namespace Swoole\Coroutine\Http {
	class Client {
		public function __construct(string $host, int $port = 0, bool $ssl = false) {}
		public function __destruct() {}
		public function set(array $settings): bool {}
		public function getDefer(): bool {}
		public function setDefer(bool $defer = true): bool {}
		public function setMethod(string $method): bool {}
		public function setHeaders(array $headers): bool {}
		public function setBasicAuth(string $username, string $password): void {}
		public function setCookies(array $cookies): bool {}
		public function setData(string|array $data): bool {}
		public function addFile(string $path, string $name, ?string $type = null, ?string $filename = null, int $offset = 0, int $length = 0): bool {}
		public function addData(string $path, string $name, ?string $type = null , ?string $filename = null): bool {}
		public function execute(string $path): bool {}
		public function getsockname(): array|false {}
		public function getpeername(): array|false {}
		public function get(string $path): bool {}
		public function post(string $path, mixed $data): bool {}
		public function download(string $path, string $file, int $offset = 0): bool {}
		public function getBody(): string|false {}
		public function getHeaders(): null|array|false {}
		public function getCookies(): null|array|false {}
		public function getStatusCode(): int|false {}
		public function getHeaderOut(): false|string {}
		#ifdef SW_USE_OPENSSL
		public function getPeerCert(): false|string {}
		#endif
		public function upgrade(string $path): bool {}
		public function push(mixed $data, int $opcode = SWOOLE_WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): bool {}
		public function recv(float $timeout = 0): bool|\Swoole\WebSocket\Frame {}
		public function close(): bool {}
	}
}
