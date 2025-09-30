<?php
namespace Swoole {
    class Lock {
        public function __construct(int $type = SWOOLE_MUTEX) {}
        public function lock(int $operation = LOCK_EX, float $timeout = -1): bool {}
        public function unlock(): bool {}
    }
}
