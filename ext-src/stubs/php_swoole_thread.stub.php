<?php
namespace Swoole {
    class Thread {
        public int $id;
        public function __construct(string $script_file, mixed ...$args) {}

        public function join(): bool {}
        public function joinable(): bool {}
        public function detach(): bool {}

        public static function getArguments(): array {}
        public static function getId(): int {}
        public static function getTsrmInfo(): array {}
    }
}
