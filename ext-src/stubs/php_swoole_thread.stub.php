<?php
namespace Swoole {
    class Thread {
        public int $id;
        private function __construct() {}

        public function join(): bool {}
        public function joinable(): bool {}
        public function detach(): bool {}
        
        public static function exec(string $script_file, mixed ...$args): Thread {}
        public static function getArguments(): array {}
        public static function getId(): int {}
    }
}
