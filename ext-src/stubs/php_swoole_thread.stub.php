<?php
namespace Swoole {
    class Thread {
        public int $id;
        private function __construct() {}

        public function join(): bool {}
        public static function run(string $script_file, mixed ...$args): Thread {}
        public static function getArguments(): array {}
        public static function getId(): int {}
    }
}
