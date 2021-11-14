<?php
namespace Swoole {
     final class Table {
        public function __construct(int $table_size, float $conflict_proportion = 0.2) {}
        public function column(string $name, int $type, int $size = 0): bool {}
        public function create(): bool {}
        public function set(string $key, array $value): bool {}
        public function get(string $key, string $field = null): array|bool|string|float|int {}
        public function del(string $key): bool {}
        public function exists(string $key): bool {}
        public function incr(string $key, string $column, mixed $incrby = 1): bool|float|int {}
        public function decr(string $key, string $column, mixed $incrby = 1): bool|float|int {}
        public function count(): int|bool {}
        public function destroy(): bool {}
        public function getSize(): int {}
        public function getMemorySize(): int {}
        public function stats(): bool|array {}
        public function rewind(): void {}
        public function next(): void {}
        public function current(): array|null {}
        public function key(): string|null {}
        public function valid(): bool {}
    }
}
