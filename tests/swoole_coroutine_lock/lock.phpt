--TEST--
swoole_coroutine_lock: shared lock serializes requests without blocking other coroutines
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Http\Server::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Lock;
use Swoole\Coroutine\WaitGroup;
use Swoole\Http\Server;
use function Swoole\Coroutine\run;

function waitForCounter(Atomic $counter, int $expected): void
{
    $deadline = microtime(true) + 5;
    while ($counter->get() !== $expected && microtime(true) < $deadline) {
        Coroutine::sleep(0.001);
    }
    Assert::same($counter->get(), $expected);
}

$attempts = new Atomic();
$active = new Atomic();
$release = new Atomic();
$ready = new Atomic();
$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(10);
$pm->parentFunc = function () use ($pm, $attempts, $active, $release) {
    try {
        run(function () use ($pm, $attempts, $active, $release) {
            $request = function (int $value) use ($pm): array {
                $client = new Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 10]);
                try {
                    Assert::true($client->get('/?value=' . $value));
                    Assert::same($client->statusCode, 200);
                    return json_decode($client->body, true, 512, JSON_THROW_ON_ERROR);
                } finally {
                    $client->close();
                }
            };
            $results = [];
            $waitGroup = new WaitGroup();
            $waitGroup->add(2);
            Coroutine::create(function () use ($request, $waitGroup, &$results) {
                try {
                    $results[1] = $request(1);
                } finally {
                    $waitGroup->done();
                }
            });
            waitForCounter($active, 1);
            Coroutine::create(function () use ($request, $waitGroup, &$results) {
                try {
                    $results[2] = $request(2);
                } finally {
                    $waitGroup->done();
                }
            });
            // Request 1 owns the lock and request 2 has reached lock(), regardless of socket scheduling.
            waitForCounter($attempts, 2);
            Assert::same($request(3), ['active' => 1]);
            $release->set(1);
            Assert::true($waitGroup->wait(10));
            Assert::same($results[1], ['result' => 'lock1']);
            Assert::same($results[2], ['result' => 'lock2']);
            Assert::same($active->get(), 0);
        });
    } finally {
        $release->set(1);
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $attempts, $active, $release, $ready) {
    swoole_async_set(['log_file' => '/dev/null']);
    $lock = new Lock(true);
    Assert::false($lock->lock());
    Assert::false($lock->unlock());
    Assert::same($lock->errCode, SWOOLE_ERROR_CO_OUT_OF_COROUTINE);
    $server = new Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'worker_num' => 4,
        'enable_coroutine' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm, $ready) {
        if ($ready->add() === 4) {
            $pm->wakeup();
        }
    });
    $server->on('Request', function ($request, $response) use ($lock, $attempts, $active, $release) {
        $value = (int) $request->get['value'];
        if ($value === 3) {
            $response->end(json_encode(['active' => $active->get()]));
            return;
        }
        $attempts->add();
        Assert::true($lock->lock());
        try {
            Assert::same($active->add(), 1);
            if ($value === 1) {
                waitForCounter($release, 1);
            }
            Assert::same($active->sub(), 0);
        } finally {
            Assert::true($lock->unlock());
        }
        $response->end(json_encode(['result' => 'lock' . $value]));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
