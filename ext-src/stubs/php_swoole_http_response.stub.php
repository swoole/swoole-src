<?php
namespace Swoole\Http {
	class Response {
		public function write(string $content): bool {}
		public function end(?string $content = null): bool {}
		public function sendfile(string $filename, int $offset = 0, int $length = 0): bool {}
		public function redirect(string $location, int $http_code = 302): bool {}
		public function cookie(string $name, string $value = '', int $expires = 0 , string $path = '/', string $domain  = '', bool $secure = false , bool $httponly = false, string $samesite = '', string $priority = ''): bool {}
		public function rawcookie(string $name, string $value = '', int $expires = 0 , string $path = '/', string $domain  = '', bool $secure = false , bool $httponly = false, string $samesite = '', string $priority = ''): bool {}
		public function header(string $key, string|array $value, bool $format = true): bool {}
		public function initHeader(): bool {}
		public function isWritable(): bool {}
		public function detach(): bool {}
		public static function create(object|array|int $server = -1, int $fd = -1): Response|false {}
		public function upgrade(): bool {}
		public function push(\Swoole\WebSocket\Frame|string $data, int $opcode = SWOOLE_WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): bool {}
		public function recv(float $timeout = 0): \Swoole\WebSocket\Frame|false|string {}
		public function close(): bool {}
		public function trailer(string $key, string $value): bool {}
		public function ping(): bool {}
		public function goaway(int $error_code = SWOOLE_HTTP2_ERROR_NO_ERROR, string $debug_data = ''): bool {}
		public function status(int $http_code, string $reason = ''): bool {}
		public function __destruct() {}
	}
}
