<?php
namespace Swoole\Redis {
    class Server {
        public function setHandler(string $command, callable $callback): bool {}
        public function getHandler(string $command): \Closure|bool {}
        public static function format(int $type, mixed $value = null): bool|string {}
    }
}
