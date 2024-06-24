<?php
namespace Swoole\Thread {
    class Barrier {
        public function __construct(int $count) {}
        public function wait(): void {}
        public function __wakeup(): void {}
    }
}
