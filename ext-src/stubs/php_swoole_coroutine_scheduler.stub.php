<?php
namespace Swoole\Coroutine {
    class Scheduler {
        public function add(callable $func, mixed ...$param): void {}
        public function parallel(int $n, callable $func, mixed ...$param): void {}
        public function set(array $settings): void {}
        public function getOptions(): ?array {}
        public function start(): bool {}
    }
}
