<?php
namespace Swoole\Coroutine {
    class System {
        public static function gethostbyname(string $domain_name, int $type = AF_INET, float $timeout = -1): false|string {}
        public static function dnsLookup(string $domain_name, float $timeout = 60, int $type = AF_INET): string|false {}
        public static function exec(string $command, bool $get_error_stream = false): array|false {}
        public static function sleep(float $seconds): bool {}
        public static function getaddrinfo(string $domain, int $family = AF_INET, int $socktype = SOCK_STREAM, int $protocol = STREAM_IPPROTO_TCP, ?string $service = null, float $timeout = -1): array|bool {}
        public static function statvfs(string $path): array {}
        public static function readFile(string $filename, int $flag = 0): false|string {}
        public static function writeFile(string $filename, string $fileContent, int $flags = 0): false|int {}
        public static function wait(float $timeout = -1): array|false {}
        public static function waitPid(int $pid, float $timeout = -1): array|false {}
        public static function waitSignal(int|array $signals, float $timeout = -1): int|false {}
        public static function waitEvent(mixed $socket, int $events = SWOOLE_EVENT_READ, float $timeout = -1): int|false {}
    }
}
