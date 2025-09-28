<?php
namespace Swoole {
    class Lock {
        public function __construct(int $type = SWOOLE_MUTEX) {}
        public function __destruct() {}
        public function lock(): bool {}
        public function lockwait(float $timeout = 1.0, int $kind = LOCK_EX): bool {}
        public function trylock(): bool {}
        public function lock_read(): bool {}
        public function trylock_read(): bool {}
        public function unlock(): bool {}
    }
}
