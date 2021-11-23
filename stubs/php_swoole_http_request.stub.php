<?php
namespace Swoole\Http {
	class Request {
		public function __destruct() {}
		public function getData(): string {}
		public static function create(array $options = []): Request|false {}
		public function parse(string $data): int|false {}
		public function isCompleted(): bool {}
		public function getMethod(): string|false {}
		public function getContent(): string|false {}
	}
}
