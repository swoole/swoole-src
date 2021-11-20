<?php
namespace Swoole {
    final class Server {
        public function __construct(string $host = '0.0.0.0', int $port = 0, int $mode = SWOOLE_PROCESS, int $sock_type = SWOOLE_SOCK_TCP) {}
        public function __destruct() {}
        public function set(array $settings): bool {}
        public function on(string $event_name, mixed $callback): bool {}
        public function getCallback(string $event_name): Closure|string|null|array {}
        public function listen(string $host, int $port, int $sock_type = SWOOLE_SOCK_TCP): bool|Server\Port {}
        public function sendMessage(string $message, int $dst_worker_id): bool {}
        public function addProcess(\Swoole\Process $process): bool|int {}
        public function addCommand(string $name, int $accepted_process_types, callable $callback): bool {}
        public function start(): bool {}
        public function stop(int $workerId = -1, bool $waitEvent = false): bool {}
        public function send(int|string $fd, string $send_data, int $serverSocket = -1): bool {}
        public function sendfile(int $conn_fd, string $filename, int $offset = 0, int $length = 0): bool {}
        public function stats(): array {}
        public function bind(int $fd, int $uid): bool {}
        public function sendto(string $ip, int $port, string $send_data, int $server_socket = -1): bool {}
        public function sendwait(int $conn_fd, string $send_data): bool {}
        public function exists(int $fd): bool {}
        public function protect(int $fd, bool $is_protected = true): bool {}
        public function close(int $fd, bool $reset = false): bool {}
        public function pause(int $fd): bool {}
        public function resume(int $fd): bool {}
        public function task(mixed $data, int $worker_id = -1, ?callable $finishCallback = null): int|bool {}
        public function taskwait(mixed $data, float $timeout = 0.5, int $worker_id = -1): string|bool {}
        public function taskWaitMulti(array $tasks, float $timeout = 0.5): bool|array {}
        public function taskCo(array $tasks, float $timeout = 0.5): array {}
        public function finish(mixed $data): bool {}
        public function reload(bool $only_reload_taskworker = false): bool {}
        public function shutdown(): bool {}
        public function heartbeat(bool $ifCloseConnection = true): bool|array {}
        public function command(string $name, int $process_id, int $process_type, mixed $data, bool $json_decode = true): bool|string {}
        public function getClientList(int $start_fd = 0, int $find_count = 10): bool|array {}
        public function getClientInfo(int $fd, int $reactor_id = -1, bool $ignoreError = false): bool|array {}
        public function getWorkerId(): int|bool {}
        public function getWorkerPid(int $worker_id = -1): int|bool {}
        public function getWorkerStatus(int $worker_id = -1): int|bool {}
        public function getManagerPid(): int {}
        public function getMasterPid(): int {}
        public function getSocket(int $port = 0): mixed {}
        public function getLastError(): int {}
    }
}

namespace Swoole\Connection {
    final class Iterator {
        public function __construct() {}
        public function __destruct() {}
        public function rewind(): void {}
        public function next(): void {}
        public function current(): int {}
        public function key(): int {}
        public function valid(): bool {}
        public function count(): int {}
        public function offsetExists(mixed $fd): bool {}
        public function offsetGet(mixed $fd): mixed {}
        public function offsetSet(mixed $fd, mixed $value): void {}
        public function offsetUnset(mixed $fd): void {}
    }
}

namespace Swoole\Server {
    final class Task {
        public function finish(mixed $data): bool {}
        public static function pack(mixed $data): string|bool {}
    }
}
