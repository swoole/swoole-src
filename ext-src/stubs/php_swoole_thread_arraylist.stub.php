<?php
namespace Swoole\Thread {
    class ArrayList implements ArrayAccess, Countable {
        public function __construct(?array $array = null) {}
        public function offsetGet(mixed $key): mixed {}
        public function offsetExists(mixed $key): bool {}
        public function offsetSet(mixed $key, mixed $value): void {}
        public function offsetUnset(mixed $key): void {}
        public function find(mixed $value): int {}
        public function count(): int {}
        public function incr(mixed $key, mixed $value = 1): mixed {}
        public function decr(mixed $key, mixed $value = 1): mixed {}
        public function clean(): void {}
        public function toArray(): array {}
    }
}
