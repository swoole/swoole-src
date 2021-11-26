<?php
namespace Swoole\Coroutine\Http {
	final class Server {
		public function __construct(string $host, int $port = 0, bool $ssl = false, bool $reuse_port = false) {}
		public function __destruct() {}
		public function set(array $settings): bool {}
		public function handle(string $pattern, callable $callback): void {}
		public function start(): bool {}
		public function shutdown(): void {}
		private function onAccept(): void {}
	}
}
