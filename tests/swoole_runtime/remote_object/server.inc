<?php

declare(strict_types=1);

require_once __DIR__ . '/../../include/lib/src/Assert.php';

class RemoteObjectTestServer extends Swoole\RemoteObject\Server
{
    public static array $releaseRequests = [];

    public function onStart(): void
    {
    }

    public function onRequest(Swoole\Http\Request $request, Swoole\Http\Response $response): void
    {
        if ($request->server['request_uri'] === '/destroy_batch') {
            self::$releaseRequests[] = unserialize($request->post['objects']);
        } elseif ($request->server['request_uri'] === '/destroy') {
            self::$releaseRequests[] = [(int) $request->post['object']];
        }
        parent::onRequest($request, $response);
    }
}

class RemoteObjectTestAggregate implements IteratorAggregate
{
    public static int $released = 0;

    public int $iteratorCount = 0;

    public function getIterator(): Traversable
    {
        $this->iteratorCount++;
        try {
            yield 'first' => 10;
            yield 'second' => 20;
            yield 'third' => 30;
        } finally {
            self::$released++;
        }
    }
}

function remote_object_test_released_iterators(): int
{
    return RemoteObjectTestAggregate::$released;
}

function remote_object_test_wait(callable $condition): void
{
    $deadline = microtime(true) + 5;
    while (!$condition()) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out waiting for remote object cleanup');
        }
        Swoole\Coroutine::sleep(0.001);
        clearstatcache();
    }
}

function remote_object_test(callable $test, array $options = []): void
{
    $socket = sys_get_temp_dir() . '/swoole-ro-' . getmypid() . '.sock';
    $process = new Swoole\Process(static function () use ($socket, $options): void {
        (new RemoteObjectTestServer($socket, 0, array_replace([
            'server_mode' => SWOOLE_BASE,
            'socket_type' => SWOOLE_SOCK_UNIX_STREAM,
            'worker_num' => 1,
            'enable_coroutine' => false,
            'log_file' => '/dev/null',
        ], $options)))->start();
    });
    $pid = $process->start();
    if (!$pid) {
        throw new RuntimeException('Failed to start remote object test server');
    }
    try {
        $deadline = microtime(true) + 5;
        do {
            $connection = @stream_socket_client('unix://' . $socket, $errno, $error, 0.1);
            if ($connection) {
                fclose($connection);
                break;
            }
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Remote object test server did not start: ' . $error);
            }
            usleep(1000);
        } while (true);
        Swoole\Coroutine::set(['hook_flags' => 0]);
        $error = null;
        Swoole\Coroutine\run(static function () use ($socket, $test, &$error): void {
            try {
                $test(new Swoole\RemoteObject\Client('unix://' . $socket), $socket);
            } catch (Throwable $e) {
                $error = $e;
            }
        });
        if ($error !== null) {
            throw $error;
        }
    } finally {
        Swoole\Process::kill($pid, SIGTERM);
        Swoole\Process::wait(true);
        if (file_exists($socket)) {
            unlink($socket);
        }
    }
}
