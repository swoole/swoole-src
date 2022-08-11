<?php
namespace Swoole {
    final class Server {
        public function __construct(string $host = '0.0.0.0', int $port = 0, int $mode = SWOOLE_PROCESS, int $sock_type = SWOOLE_SOCK_TCP) {}
        public function __destruct() {}
        public function set(array $settings): bool {}
        public function on(string $event_name, callable $callback): bool {}
        public function getCallback(string $event_name): \Closure|string|null|array {}
        public function listen(string $host, int $port, int $sock_type): false|Server\Port {}
        public function sendMessage(mixed $message, int $dst_worker_id): bool {}
        public function addProcess(\Swoole\Process $process): int {}
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
        public function task(mixed $data, int $taskWorkerIndex = -1, ?callable $finishCallback = null): int|false {}
        public function taskwait(mixed $data, float $timeout = 0.5, int $taskWorkerIndex = -1): string|false {}
        public function taskWaitMulti(array $tasks, float $timeout = 0.5): false|array {}
        public function taskCo(array $tasks, float $timeout = 0.5): array|false {}
        public function finish(mixed $data): bool {}
        public function reload(bool $only_reload_taskworker = false): bool {}
        public function shutdown(): bool {}
        public function heartbeat(bool $ifCloseConnection = true): false|array {}
        public function command(string $name, int $process_id, int $process_type, mixed $data, bool $json_decode = true): false|string {}
        public function getClientList(int $start_fd = 0, int $find_count = 10): false|array {}
        public function getClientInfo(int $fd, int $reactor_id = -1, bool $ignoreError = false): false|array {}
        public function getWorkerId(): int|false {}
        public function getWorkerPid(int $worker_id = -1): int|false {}
        public function getWorkerStatus(int $worker_id = -1): int|false {}
        public function getManagerPid(): int {}
        public function getMasterPid(): int {}
        #ifdef SWOOLE_SOCKETS_SUPPORT
        public function getSocket(int $port = 0): false|\Socket {}
        #endif
        public function getLastError(): int {}
    }
}

namespace Swoole\Connection {
    final class Iterator {
        public function __construct() {}
        public function __destruct() {}
        public function rewind(): void {}
        public function next(): void {}
        public function current(): mixed {}
        public function key(): mixed {}
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
        public static function pack(mixed $data): string|false {}
    }
}
