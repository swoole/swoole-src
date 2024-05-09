<?php
namespace Swoole\Thread {
    class ArrayList implements ArrayAccess, Countable {
        public function __construct() {}
        public function offsetGet(mixed $key): mixed {}
        public function offsetExists(mixed $key): bool {}
        public function offsetSet(mixed $key, mixed $value): void {}
        public function offsetUnset(mixed $key): void {}
        public function count(): int {}
        public function clean(): void {}
        public function __wakeup(): void {}
    }
}
