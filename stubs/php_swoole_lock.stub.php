<?php
namespace Swoole {
    class Lock {
        public function __construct(int $type = SWOOLE_MUTEX, string $filename = '') {}
        public function __destruct() {}
        public function lock(): bool {}
        public function locakwait(float $timeout = 1.0): bool {}
        public function trylock(): bool {}
        public function lock_read(): bool {}
        public function trylock_read(): bool {}
        public function unlock(): bool {}
        public function destroy(): void {}
    }
}
