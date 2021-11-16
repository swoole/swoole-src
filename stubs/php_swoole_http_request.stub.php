<?php
/**
 * @strict-properties
 * @not-serializable
 */
namespace Swoole\Http {
	class Request {
		public function __destruct() {}
		public function getData(): string {}
		public function create(array $options = []): Request|bool {}
		public static function create(array $options = []): Request|bool {}
		public function parse(string $data): int|bool {}
		public function isCompleted(): bool {}
		public function getMethod(): string|bool {}
		public function getContent(): string|bool {}
	}
}
