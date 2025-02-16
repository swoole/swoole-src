<?php
namespace Swoole\Coroutine {
    class Lock {
        public function __construct(bool $shared = false) {}
        public function __destruct() {}
        public function lock(): bool {}
        public function trylock(): bool {}
        public function unlock(): bool {}
    }
}
