<?php
namespace Swoole\Coroutine {
    class System {
        public static function gethostbyname(string $domain_name, int $type = AF_INET, float $timeout = -1): bool|string {}
        public static function dnsLookup(string $domain_name, float $timeout = 60, int $type = AF_INET): string|bool {}
        public static function exec(string $command, bool $get_error_stream = false): array|bool {}
        public static function sleep(float $seconds): bool {}
        public static function getaddrinfo(string $domain, int $family = AF_INET, int $socktype = SOCK_STREAM, int $protocol = STREAM_IPPROTO_TCP, ?string $service = null, float $timeout = -1): array|bool {}
        public static function statvfs(string $path): array {}
        public static function readFile(string $filename, int $flag = 0): bool|string {}
        public static function writeFile(string $filename, string $fileContent, int $flags = 0): bool|int {}
        public static function wait(float $timeout = -1): array|bool {}
        public static function waitPid(int $pid, float $timeout = -1): array|bool {}
        public static function waitSignal(int $signo, float $timeout = -1): bool {}
        public static function waitEvent(mixed $socket, int $events = SWOOLE_EVENT_READ, float $timeout = -1): int|bool {}
        /**
         * @param resource $handle
         * @deprecated
         */
        public static function fread($handle, int $length = 0): string|bool {}
        /**
         * @param resource $handle
         * @deprecated
         */
        public static function fwrite($handle, string $data, int $length = 0): int|bool {}
        /**
         * @param resource $handle
         * @deprecated
         */
        public static function fgets($handle): string|bool {}
    }
}
