<?php
namespace Swoole\Coroutine {
    class Scheduler {
        public function add(callable $func, mixed ...$param): ?bool {}
        public function parallel(int $n, callable $func, mixed ...$param): ?bool {}
        public function set(array $settings): ?bool {}
        public function getOptions(): ?array {}
        public function start(): bool {}
    }
}
