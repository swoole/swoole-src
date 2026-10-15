--TEST--
swoole_runtime/remote_object: the 100ms fallback timer retains the client through coroutine exit
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\RemoteObject\Client;
use SwooleTest\Assert;

class RemoteObjectLifetimeTracked
{
    public function __construct(private string $trace)
    {
    }

    public function __destruct()
    {
        // Distinguish a successful batch from the server's fallback connection-close cleanup.
        file_put_contents($this->trace, json_encode([
            'batches' => array_map('count', RemoteObjectTestServer::$releaseRequests),
            'released_at' => hrtime(true),
        ]));
    }
}

$trace = tempnam(sys_get_temp_dir(), 'swoole-ro-lifetime-');
try {
    foreach ([true, false] as $enableCoroutine) {
        swoole_async_set(['enable_coroutine' => $enableCoroutine]);
        file_put_contents($trace, '');
        $reference = null;
        $queuedAt = 0;
        remote_object_test(static function (Client $unused, string $socket) use ($trace, &$reference, &$queuedAt): void {
            $client = new Client('unix://' . $socket);
            $reference = WeakReference::create($client);
            $object = $client->create(RemoteObjectLifetimeTracked::class, $trace);
            $queuedAt = hrtime(true);
            unset($client, $object);
            Assert::notNull($reference->get());
            // No further I/O: the timer must run even after the last user coroutine has ended.
        });
        Assert::null($reference->get());
        $result = json_decode(file_get_contents($trace), true);
        Assert::same($result['batches'], [1]);
        // Allow timer clock granularity, but reject an immediate or short-delay flush.
        Assert::greaterThanEq($result['released_at'] - $queuedAt, 90_000_000);
    }
} finally {
    unlink($trace);
}
echo "DONE\n";
?>
--EXPECT--
DONE
