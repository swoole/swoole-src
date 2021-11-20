<?php
namespace Swoole\Server {
    class Port {
        private function __construct() {}
        public function __destruct() {}
        public function set(array $settings): ?bool {}
        public function on(string $event_name, callable $callback): bool {}
        public function getCallback(string $event_name): null|\Closure {}
        public function getSocket(): bool|object {}
    }
}
