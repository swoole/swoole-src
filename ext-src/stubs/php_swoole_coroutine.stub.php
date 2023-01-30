<?php
namespace Swoole {
    class Coroutine {
        public static function create(callable $func, mixed ...$param): int|false {}
        public static function defer(callable $callback): void {}
        public static function set(array $options): void {}
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
        public static function getPcid(int $cid = 0): false|int {}
        public static function getContext(int $cid = 0): \Swoole\Coroutine\Context|null {}
        public static function getBackTrace(int $cid = 0, int $options = DEBUG_BACKTRACE_PROVIDE_OBJECT, int $limit = 0): array|false {}
        public static function printBackTrace(int $cid = 0, int $options = 0, int $limit = 0): void {}
        public static function getElapsed(int $cid = 0): int {}
        public static function getStackUsage(int $cid = 0): false|int {}
        public static function list(): \Swoole\Coroutine\Iterator {}
        public static function listCoroutines(): \Swoole\Coroutine\Iterator {}
        public static function enableScheduler(): bool {}
        public static function disableScheduler(): bool {}
        public static function getExecuteTime(): int {}
    }

    class ExitException {
        public function getFlags(): int {}
        public function getStatus(): mixed {}
    }
}
