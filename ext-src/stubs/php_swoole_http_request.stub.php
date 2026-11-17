<?php
namespace Swoole\Http {
	class Request {
		public function __destruct() {}
		public function getData(): string|false {}
		public static function create(array $options = []): Request {}
		public function parse(string $data): int|false {}
		public function isCompleted(): bool {}
		public function getMethod(): string|false {}
		public function getContent(): string|false {}
		public function recv(float $timeout = -1): string|false {}
	}
}
