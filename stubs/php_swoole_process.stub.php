<?php
namespace Swoole {
    class Process {
        public function __construct(callable $callback, bool $redirect_stdin_and_stdout = false, int $pipe_type = SOCK_DGRAM, bool $enable_coroutine = false) {}
        public function __destruct() {}
        public function useQueue(int $key = 0, int $mode = 2, int $capacity = -1): bool {}
        public function statQueue(): array|bool {}
        public function freeQueue(): bool {}
        public function pop(int $size = 65536): bool|string {}
        public function push(string $data): bool {}
        public function kill(int $pid, int $signal_no = SIGTERM): bool {}
        public function signal(int $signal_no, ?callable $callback = null): bool {}
        public function alarm(int $usec, int $type = 0): bool {}
        public function wait(bool $blocking = true): array|bool {}
        public function daemon(bool $nochdir = true, bool $noclose = true, array $pipes = []): bool {}
        public function setAffinity(array $cpu_settings): bool {}
        public function set(array $settings): ?bool {}
        public function setTimeout(float $seconds): bool {}
        public function setBlocking(bool $blocking): ?bool {}
        public function setPriority(int $which, int $priority):bool {}
        public function getPriority(int $which): bool|int {}
        public function start(): bool|int {}
        public function write(string $data): bool|int {}
        public function read(int $size = 8192): bool|string {}
        public function close(int $which = 0): bool {}
        public function exit(int $exit_code = 0): bool {}
        public function exec(string $exec_file, array $args): bool {}
        public function exportSocket(): \Swoole\Coroutine\Socket|bool {}
        public function name(string $process_name): bool {}
    }
}
