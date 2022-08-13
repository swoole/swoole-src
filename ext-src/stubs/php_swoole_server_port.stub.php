<?php
namespace Swoole\Server {
    class Port {
        private function __construct() {}
        public function __destruct() {}
        public function set(array $settings): void {}
        public function on(string $event_name, callable $callback): bool {}
        public function getCallback(string $event_name): \Closure|null {}
        #ifdef SWOOLE_SOCKETS_SUPPORT
        public function getSocket(): \Socket|false {}
        #endif
    }
}
