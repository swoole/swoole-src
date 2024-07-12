<?php
namespace Swoole\Thread {
    class Map implements ArrayAccess, Countable {
        public function __construct(?array $array = null) {}
        public function offsetGet(mixed $key): mixed {}
        public function offsetExists(mixed $key): bool {}
        public function offsetSet(mixed $key, mixed $value): void {}
        public function offsetUnset(mixed $key): void {}
        public function find(mixed $value): mixed {}
        public function count(): int {}
        public function keys(): array {}
        public function values(): array {}
        public function incr(mixed $key, mixed $value = 1): mixed {}
        public function decr(mixed $key, mixed $value = 1): mixed {}
        public function add(mixed $key, mixed $value): bool {}
        public function update(mixed $key, mixed $value): bool {}
        public function clean(): void {}
        public function toArray(): array {}
    }
}
