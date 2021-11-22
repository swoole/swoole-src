<?php
namespace Swoole {
    class Coroutine {
        public static function create(callable $func, mixed ...$param): int|bool {}
        public static function defer(callable $callback): ?bool {}
        public static function set(array $options): ?bool {}
        public static function getOptions(): ?array {}
        public static function exists(int $cid): bool {}
        public static function yield(): bool {}
        public static function cancel(int $cid): bool {}
        public static function join(array $cid_array, float $timeout = -1): bool {}
        public static function isCanceled(): bool {}
        public static function suspend(): bool {}
        public static function resume(int $cid): bool {}
        public static function stats(): array {}
        public static function getCid(): int {}
        public static function getuid(): int {}
        public static function getPcid(int $cid = 0): bool|int {}
        public static function getContext(int $cid = 0): \Swoole\Coroutine\Context|bool|null {}
        public static function getBackTrace(int $cid = 0, int $options = DEBUG_BACKTRACE_PROVIDE_OBJECT, int $limit = 0): array|bool {}
        public static function printBackTrace(int $cid = 0, int $options = DEBUG_BACKTRACE_PROVIDE_OBJECT, int $limit = 0): ?bool {}
        public static function getElapsed(int $cid = 0): int|bool {}
        public static function getStackUsage(int $cid = 0): bool|int {}
        public static function list(): \Swoole\Coroutine\Iterator {}
        public static function listCoroutines(): \Swoole\Coroutine\Iterator {}
        public static function enableScheduler(): bool {}
        public static function disableScheduler(): bool {}
    }

    class ExitException {
        public function getFlags(): mixed {}
        public function getStatus(): int {}
    }
}
