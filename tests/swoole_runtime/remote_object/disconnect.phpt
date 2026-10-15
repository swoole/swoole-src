--TEST--
swoole_runtime/remote_object: disconnect releases objects, resources and iterators without affecting other clients
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires fork and Unix sockets');
if (!class_exists(Swoole\RemoteObject::class)) die('skip requires the Swoole library');
if (!function_exists('proc_open')) die('skip requires proc_open');
?>
--FILE--
<?php
require __DIR__ . '/server.inc';

use Swoole\Coroutine;
use Swoole\RemoteObject\Client;
use SwooleTest\Assert;

// A throwing remote destructor is logged by the server, but must not stop the remaining cleanup.
ini_set('error_log', '/dev/null');

class RemoteObjectDisconnectTracked implements IteratorAggregate
{
    public function __construct(public string $name, private string $trace, private bool $throw = false)
    {
    }

    public function __clone(): void
    {
        $this->name .= '-clone';
    }

    public function __destruct()
    {
        file_put_contents($this->trace, 'destroy:' . $this->name . "\n", FILE_APPEND | LOCK_EX);
        if ($this->throw) {
            throw new RuntimeException('remote destructor failed');
        }
    }

    public function child(): self
    {
        return new self($this->name . '-child', $this->trace);
    }

    public function __get(string $property): self
    {
        return new self($this->name . '-' . $property, $this->trace);
    }

    public function getIterator(): Traversable
    {
        try {
            yield $this->name;
        } finally {
            file_put_contents($this->trace, 'iterator:' . $this->name . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    public function slowChild(string $started, string $release): self
    {
        touch($started);
        $deadline = microtime(true) + 5;
        while (!is_file($release)) {
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Timed out waiting for the disconnected request');
            }
            Coroutine::sleep(0.001);
            clearstatcache(true, $release);
        }
        return $this->child();
    }
}

function remote_object_disconnect_object(string $name, string $trace): RemoteObjectDisconnectTracked
{
    return new RemoteObjectDisconnectTracked($name, $trace);
}

function remote_object_disconnect_wait(callable $condition): void
{
    $deadline = microtime(true) + 5;
    while (!$condition()) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out waiting for remote object cleanup');
        }
        Coroutine::sleep(0.001);
        clearstatcache();
    }
}

$trace = tempnam(sys_get_temp_dir(), 'swoole-ro-disconnect-');
$started = $trace . '.started';
$release = $trace . '.release';

try {
    foreach ([false, true] as $eventObject) {
        file_put_contents($trace, '');
        remote_object_test(static function (Client $client, string $socket) use ($trace, $started, $release): void {
            $survivor = $client->create(RemoteObjectDisconnectTracked::class, 'survivor', $trace);
            $code = <<<'PHP'
Swoole\Coroutine\run(static function () use ($argv): void {
    $client = new Swoole\RemoteObject\Client('unix://' . $argv[1]);
    $objects = [];
    $objects[] = $client->create('RemoteObjectDisconnectTracked', 'throwing', $argv[2], true);
    $objects[] = $client->create('RemoteObjectDisconnectTracked', 'root', $argv[2]);
    $objects[] = clone $objects[1];
    $objects[] = $objects[1]->child();
    $objects[] = $objects[1]->property;
    $objects[] = $client->call('remote_object_disconnect_object', 'function', $argv[2]);
    $iterator = $client->create('RemoteObjectDisconnectTracked', 'iterator', $argv[2]);
    $iterator->rewind();
    $resource = $client->call('tmpfile');
    $normal = $client->create('RemoteObjectDisconnectTracked', 'normal', $argv[2]);
    unset($normal);
    echo json_encode($client->call('stream_get_meta_data', $resource)['uri']), "\n";
    fflush(STDOUT);
    Swoole\Coroutine::sleep(30);
});
PHP;
            $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' ' . getenv('TEST_PHP_EXTRA_ARGS')
                . ' -r ' . escapeshellarg($code) . ' ' . escapeshellarg($socket) . ' ' . escapeshellarg($trace);
            $process = proc_open($command, [
                0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
            ], $pipes);
            Assert::true(is_resource($process));
            try {
                stream_set_timeout($pipes[1], 10);
                $resourcePath = json_decode(fgets($pipes[1]) ?: 'null', true);
                Assert::true(is_string($resourcePath));
                Assert::true(is_file($resourcePath));
                proc_terminate($process, SIGKILL);
                proc_close($process);
                $process = null;
                $expected = [
                    'destroy:throwing', 'destroy:root', 'destroy:root-clone', 'destroy:root-child',
                    'destroy:root-property', 'destroy:function', 'destroy:iterator', 'iterator:iterator', 'destroy:normal',
                ];
                sort($expected);
                remote_object_disconnect_wait(static function () use ($trace, $expected, $resourcePath): bool {
                    $events = file($trace, FILE_IGNORE_NEW_LINES);
                    sort($events);
                    return $events === $expected && !is_file($resourcePath);
                });
                Assert::same($survivor->name, 'survivor');
            } finally {
                if (is_resource($process)) {
                    proc_terminate($process, SIGKILL);
                    proc_close($process);
                }
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
            }

            // The connection closes while the method is suspended, before it returns another object.
            $http = new Swoole\Coroutine\Http\Client('unix://' . $socket);
            $http->setHeaders(['client-id' => 'in-flight', 'coroutine-id' => (string) Coroutine::getCid()]);
            Assert::true($http->post('/new', [
                'class' => RemoteObjectDisconnectTracked::class,
                'args' => serialize(['in-flight', $trace]),
            ]));
            $objectId = unserialize($http->body)['object'];
            $http->setDefer();
            Assert::true($http->post('/call_method', [
                'object' => $objectId, 'method' => 'slowChild', 'args' => serialize([$started, $release]),
            ]));
            remote_object_disconnect_wait(static fn (): bool => is_file($started));
            $http->close();
            Coroutine::sleep(0.05);
            touch($release);
            remote_object_disconnect_wait(static function () use ($trace): bool {
                $events = file($trace, FILE_IGNORE_NEW_LINES);
                return in_array('destroy:in-flight', $events, true) && in_array('destroy:in-flight-child', $events, true);
            });
            Assert::same($survivor->name, 'survivor');
        }, [
            'server_mode' => SWOOLE_PROCESS,
            'worker_num' => 2,
            'enable_coroutine' => true,
            'event_object' => $eventObject,
        ]);
        unlink($started);
        unlink($release);
    }
} finally {
    foreach ([$trace, $started, $release] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
