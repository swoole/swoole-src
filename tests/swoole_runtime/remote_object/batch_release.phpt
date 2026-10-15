--TEST--
swoole_runtime/remote_object: releases use the queue limit with a fallback timer and share the client lock
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\Coroutine;
use Swoole\RemoteObject\Client;
use SwooleTest\Assert;

ini_set('error_log', '/dev/null');

class RemoteObjectBatchTracked
{
    public function __construct(
        private string $trace,
        private bool $throw = false,
        private string $started = '',
        private string $release = ''
    ) {
    }

    public function __destruct()
    {
        if ($this->started !== '') {
            touch($this->started);
            $deadline = microtime(true) + 5;
            while (!is_file($this->release)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Timed out waiting for the release batch');
                }
                Coroutine::sleep(0.001);
                clearstatcache(true, $this->release);
            }
        }
        file_put_contents($this->trace, "released\n", FILE_APPEND | LOCK_EX);
        if ($this->throw) {
            throw new RuntimeException('Remote destructor failed');
        }
    }
}

function remote_object_batch_make(int $count, string $trace): array
{
    return array_map(static fn () => new RemoteObjectBatchTracked($trace), range(1, $count));
}

function remote_object_batch_requests(): array
{
    return RemoteObjectTestServer::$releaseRequests;
}

$trace = tempnam(sys_get_temp_dir(), 'swoole-ro-batch-');
$started = $trace . '.started';
$release = $trace . '.release';
try {
    remote_object_test(static function (Client $client, string $socket) use ($trace, $started, $release): void {
        $observer = new Client('unix://' . $socket);
        $released = static fn (): int => count(file($trace));

        // A normal call must not flush the queue; releases across I/O share the same fallback timer.
        $objects = $client->call('remote_object_batch_make', 10, $trace);
        for ($i = 0; $i < 5; $i++) {
            unset($objects[$i]);
        }
        Assert::same($client->call('remote_object_batch_requests'), []);
        unset($objects);
        remote_object_test_wait(static fn (): bool => $released() === 10);
        Assert::same(array_map('count', $observer->call('remote_object_batch_requests')), [10]);

        // Reaching 16 releases flushes synchronously, without waiting for another event-loop turn.
        $objects = $client->call('remote_object_batch_make', 17, $trace);
        $timerCount = Swoole\Timer::stats()['num'];
        for ($i = 0; $i < 16; $i++) {
            unset($objects[$i]);
        }
        Assert::same($released(), 26);
        Assert::same(Swoole\Timer::stats()['num'], $timerCount);
        unset($objects);
        remote_object_test_wait(static fn (): bool => $released() === 27);
        Assert::same(array_map('count', $observer->call('remote_object_batch_requests')), [10, 16, 1]);

        // Duplicate handles and already released IDs are harmless; a throwing destructor cannot stop the batch.
        $throwing = $client->create(RemoteObjectBatchTracked::class, $trace, true);
        $normal = $client->create(RemoteObjectBatchTracked::class, $trace);
        $twin = unserialize(serialize($normal));
        $old = $client->create(RemoteObjectBatchTracked::class, $trace);
        $client->execute('/destroy', ['object' => $old->getObjectId()]);
        unset($throwing, $normal, $twin, $old);
        remote_object_test_wait(static fn (): bool => $released() === 30);
        $batches = $observer->call('remote_object_batch_requests');
        Assert::same(array_map('count', $batches), [10, 16, 1, 1, 3]);

        // While one batch is suspended, another full batch and a normal request must serialize on the same socket.
        $slow = $client->create(RemoteObjectBatchTracked::class, $trace, false, $started, $release);
        $objects = $client->call('remote_object_batch_make', 16, $trace);
        unset($slow);
        remote_object_test_wait(static fn (): bool => is_file($started));
        $done = new Coroutine\Channel(2);
        $pending = new Coroutine\Channel(1);
        $pending->push($objects);
        unset($objects);
        Coroutine::create(static function () use ($pending, $done): void {
            $objects = $pending->pop();
            unset($objects);
            $done->push(true);
        });
        Coroutine::create(static fn () => $done->push($client->ping()));
        touch($release);
        Assert::true($done->pop(5));
        Assert::true($done->pop(5));
        remote_object_test_wait(static fn (): bool => $released() === 47);
        Assert::same(array_map('count', $observer->call('remote_object_batch_requests')), [10, 16, 1, 1, 3, 1, 16]);
        Assert::true($client->ping());
    }, ['enable_coroutine' => true]);
} finally {
    foreach ([$trace, $started, $release] as $path) {
        if (is_file($path)) {
            unlink($path);
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
