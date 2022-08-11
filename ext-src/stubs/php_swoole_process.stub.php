<?php
namespace Swoole {
    class Process {
        public function __construct(callable $callback, bool $redirect_stdin_and_stdout = false, int $pipe_type = SOCK_DGRAM, bool $enable_coroutine = false) {}
        public function __destruct() {}
        public function useQueue(int $key = 0, int $mode = 2, int $capacity = -1): bool {}
        public function statQueue(): array|false {}
        public function freeQueue(): bool {}
        public function pop(int $size = 65536): string|false {}
        public function push(string $data): bool {}
        public static function kill(int $pid, int $signal_no = SIGTERM): bool {}
        public static function signal(int $signal_no, ?callable $callback = null): bool {}
        public static function alarm(int $usec, int $type = 0): bool {}
        public static function wait(bool $blocking = true): array|false {}
        public static function daemon(bool $nochdir = true, bool $noclose = true, array $pipes = []): bool {}
        #ifdef HAVE_CPU_AFFINITY
        public static function setAffinity(array $cpu_settings): bool {}
        #endif
        public function set(array $settings): void {}
        public function setTimeout(float $seconds): bool {}
        public function setBlocking(bool $blocking): void {}
        public function setPriority(int $which, int $priority): bool {}
        public function getPriority(int $which): int {}
        public function start(): bool|int {}
        public function write(string $data): false|int {}
        public function read(int $size = 8192): false|string {}
        public function close(int $which = 0): bool {}
        public function exit(int $exit_code = 0): void {}
        public function exec(string $exec_file, array $args): bool {}
        public function exportSocket(): \Swoole\Coroutine\Socket|false {}
        public function name(string $process_name): bool {}
    }
}
