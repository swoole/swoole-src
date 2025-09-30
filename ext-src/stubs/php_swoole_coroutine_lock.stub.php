<?php
namespace Swoole\Coroutine {
    class Lock {
        public function __construct(bool $shared = false) {}
        public function lock(int $operation = LOCK_EX, float $timeout = 1.0): bool {}
        public function unlock(): bool {}
    }
}
