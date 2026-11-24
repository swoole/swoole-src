<?php
namespace Swoole {
    class Thread {
        public int $id;
        /**
         * Registered internal function names and public static methods of internal
         * classes are called with $args. Other strings are executed as script paths.
         */
        public function __construct(string $entry, mixed ...$args) {}

        public function join(): bool {}
        public function joinable(): bool {}
        public function getExitStatus(): int {}
        public function getResult(): mixed {}
        public function isAlive(): bool {}
        public function detach(): bool {}

        public static function getArguments(): ?array {}
        public static function getId(): int {}
        public static function getInfo(): array {}
        public static function activeCount(): int {}
        public static function yield(): void {}

        public static function setName(string $name): bool {}
        #ifdef HAVE_CPU_AFFINITY
        public static function setAffinity(array $cpu_settings): bool {}
        public static function getAffinity(): array {}
        #endif
        public static function setPriority(int $priority, int $policy = -1): bool {}
        public static function getPriority(): array {}
        public static function getNativeId(): int {}
    }
}
