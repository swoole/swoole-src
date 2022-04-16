<?php
namespace Swoole\Coroutine {
	class Channel {
		public function __construct(int $size = 1) {}
		public function push(mixed $data, float $timeout = -1): bool {}
		public function pop(float $timeout = -1): mixed {}
		public function stats(): array {}
		public function close(): bool {}
		public function length(): int {}
		public function isEmpty(): bool {}
		public function isFull(): bool {}
	}
}
