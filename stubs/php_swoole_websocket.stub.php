<?php
namespace Swoole\WebSocket {
	class Server {
		public function push(int $fd, \Swoole\WebSocket\Frame|string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): bool {}
		public function isEstablished(int $fd): bool {}
		public static function pack(\Swoole\WebSocket\Frame|string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): string {}
        public static function unpack(string $data): \Swoole\WebSocket\Frame {}
		public function disconnect(int $fd, int $code = SWOOLE_WEBSOCKET_CLOSE_NORMAL, string $reason = ""): bool {}
	}

	class Frame {
		public function __toString(): string {}
		public static function pack(\Swoole\WebSocket\Frame|string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): string {}
        public static function unpack(string $data): \Swoole\WebSocket\Frame {}
	}
}
