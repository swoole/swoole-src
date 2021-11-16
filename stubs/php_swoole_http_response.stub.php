<?php
/**
 * @strict-properties
 * @not-serializable
 */
namespace Swoole\Http {
	class Response {
		public function write(mixed $content): bool {}
		public function end(?mixed $content = null): bool {}
		public function sendfile(string $filename, int $offset = 0, int $length = 0): bool {}
		public function redirect(mixed $location, ?mixed $http_code = 302): mixed {}
		public function cookie(string $name, string $value = '', int $expire = 0 , string $path = '/', string $domain  = '', bool $secure = false , bool $httponly = false, string $samesite = '', string $priority = ''): bool {}
		public function rawcookie(string $name, string $value = '', int $expire = 0 , string $path = '/', string $domain  = '', bool $secure = false , bool $httponly = false, string $samesite = '', string $priority = ''): bool {}
		public function header(string $key, mixed $value, bool $format = true): bool {}
		public function initHeader(): bool {}
		public function isWritable(): bool {}
		public function detach(): bool {}
		public function create(mixed $server = -1, int $fd = -1): Response|bool {}
		public function upgrade(): bool {}
		public function push(mixed $data, int $opcode = SWOOLE_WEBSOCKET_OPCODE_TEXT, int $flags = 1): bool {}
		public function recv(float $timeout = -1): \Swoole\WebSocket\Frame|bool|string {}
		public function close(): bool {}
		public function trailer(string $key, string $value): array|bool {}
		public function ping(): bool {}
		public function goaway(int $error_code = SWOOLE_HTTP2_ERROR_NO_ERROR, string $debug_data = ''): bool {}
		public function status(int $http_code, string $reason = ''): bool {}
		public function __destruct() {}
	}
}
