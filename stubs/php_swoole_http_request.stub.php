<?php
namespace Swoole\Http {
	class Request {
		public function __destruct() {}
		public function getData(): string {}
		public static function create(array $options = []): Request|bool {}
		public function parse(string $data): int|bool {}
		public function isCompleted(): bool {}
		public function getMethod(): string|bool {}
		public function getContent(): string|bool {}
	}
}
