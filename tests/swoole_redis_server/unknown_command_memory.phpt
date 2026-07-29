--TEST--
swoole_redis_server: rejected commands do not leak request memory
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

const REQUEST_COUNT = 256;
const PAYLOAD_SIZE = 8192;
const MAX_MEMORY_GROWTH = 1024 * 1024;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm): void {
    $socket = stream_socket_client(
        'tcp://127.0.0.1:' . $pm->getFreePort(),
        $errorCode,
        $errorMessage,
        1
    );
    Assert::assert(is_resource($socket));
    stream_set_timeout($socket, 1);

    $memoryRequest = "*1\r\n$6\r\nMEMORY\r\n";
    $payload = str_repeat('A', PAYLOAD_SIZE);
    $unknownRequest = "*2\r\n$7\r\nUNKNOWN\r\n$" . strlen($payload) . "\r\n{$payload}\r\n";
    $longCommand = str_repeat('X', 64);
    $longCommandRequest =
        "*2\r\n$" . strlen($longCommand) . "\r\n{$longCommand}\r\n" .
        "$" . strlen($payload) . "\r\n{$payload}\r\n";

    fwrite($socket, $memoryRequest);
    $before = (int) substr(fgets($socket), 1);

    for ($i = 0; $i < REQUEST_COUNT; $i++) {
        Assert::same(fwrite($socket, $unknownRequest), strlen($unknownRequest));
        Assert::string(fgets($socket));
    }

    fwrite($socket, $memoryRequest);
    $after = (int) substr(fgets($socket), 1);

    Assert::lessThan($after - $before, MAX_MEMORY_GROWTH);

    for ($i = 0; $i < REQUEST_COUNT; $i++) {
        $commandSocket = stream_socket_client(
            'tcp://127.0.0.1:' . $pm->getFreePort(),
            $errorCode,
            $errorMessage,
            1
        );
        Assert::assert(is_resource($commandSocket));
        stream_set_timeout($commandSocket, 1);
        Assert::same(fwrite($commandSocket, $longCommandRequest), strlen($longCommandRequest));
        Assert::same(stream_get_contents($commandSocket), '');
        fclose($commandSocket);
    }

    fwrite($socket, $memoryRequest);
    $afterLongCommands = (int) substr(fgets($socket), 1);
    Assert::lessThan($afterLongCommands - $after, MAX_MEMORY_GROWTH);

    fclose($socket);
    $pm->kill();
};

$pm->childFunc = function () use ($pm): void {
    set_error_handler(
        static fn(int $severity, string $message): bool =>
            str_contains($message, 'command [XXXXXXXX...](length=64) is too long'),
        E_WARNING
    );
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
        'worker_num' => 1,
    ]);
    $server->setHandler('MEMORY', static function (): string {
        gc_collect_cycles();
        gc_mem_caches();
        return Server::format(Server::INT, memory_get_usage());
    });
    $server->on('WorkerStart', function () use ($pm): void {
        $pm->wakeup();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
