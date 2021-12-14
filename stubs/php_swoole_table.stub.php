<?php
namespace Swoole {
     final class Table {
        public function __construct(int $table_size, float $conflict_proportion = 0.2) {}
        public function column(string $name, int $type, int $size = 0): bool {}
        public function create(): bool {}
        public function set(string $key, array $value): bool {}
        public function get(string $key, ?string $field = null): array|false|string|float|int {}
        public function del(string $key): bool {}
        public function exists(string $key): bool {}
        public function incr(string $key, string $column, int|float $incrby = 1): float|int {}
        public function decr(string $key, string $column, int|float $incrby = 1): float|int {}
        public function count(): int {}
        public function destroy(): bool {}
        public function getSize(): int {}
        public function getMemorySize(): int {}
        public function stats(): false|array {}
        public function rewind(): void {}
        public function next(): void {}
        public function current(): mixed {}
        public function key(): mixed {}
        public function valid(): bool {}
    }
}
