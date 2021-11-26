<?php
namespace Swoole {
    class Atomic {
        public function __construct(int $value = 0) {}
        public function add(int $add_value = 1): int {}
        public function sub(int $sub_value = 1): int {}
        public function get(): int {}
        public function set(int $value): void {}
        public function cmpset(int $cmp_value, int $new_value): bool {}
        public function wait(float $timeout = 1.0): bool {}
        public function wakeup(int $count = 1): bool {}
    }
}

namespace Swoole\Atomic {
    class Long {
        public function __construct(int $value = 0) {}
        public function add(int $add_value = 1): int {}
        public function sub(int $sub_value = 1): int {}
        public function get(): int {}
        public function set(int $value): void {}
        public function cmpset(int $cmp_value, int $new_value): bool {}
    }
}
