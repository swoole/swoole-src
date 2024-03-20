<?php
namespace Swoole {
    class Thread {
        public int $id;
        private function __construct() {}

        public function join(): bool {}
        public function joinable(): bool {}
        public function detach(): bool {}

        public static function exec(string $script_file, mixed ...$args): Thread {}
        public static function getArguments(): array {}
        public static function getId(): int {}
    }
}

namespace Swoole\Thread {
    class Map implements ArrayAccess, Countable {
        public function __construct(int $key_type) {}
        public function offsetGet(mixed $key): mixed {}
        public function offsetExists(mixed $key): bool {}
        public function offsetSet(mixed $key, mixed $value): void {}
        public function offsetUnset(mixed $key): void {}
        public function count(): int {}
        public function __wakeup(): void {}
    }
    class ArrayList implements ArrayAccess, Countable {
        public function __construct() {}
        public function offsetGet(mixed $key): mixed {}
        public function offsetExists(mixed $key): bool {}
        public function offsetSet(mixed $key, mixed $value): void {}
        public function offsetUnset(mixed $key): void {}
        public function count(): int {}
        public function __wakeup(): void {}
    }
}
