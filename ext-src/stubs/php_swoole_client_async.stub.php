<?php
namespace Swoole\Async {
	class Client extends \Swoole\Client {
		public function __construct(int $type) {}
		public function __destruct() {}
        public function connect(string $host, int $port = 0, float $timeout = 0.5, int $sock_flag = 0): bool {}
        public function on(string $host, callable $callback): bool {}
        public function enableSSL(?callable $onSslReady = null): bool {}
		public function isConnected(): bool {}
        public function sleep(): bool {}
        public function wakeup(): bool {}
		public function close(bool $force = false): bool {}
	}
}
