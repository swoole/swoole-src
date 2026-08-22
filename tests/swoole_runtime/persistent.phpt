--TEST--
swoole_runtime: socket persistent then destruct
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$map = [];
$activeCallbacks = 0;
$clientName = 'swoole-runtime-persistent-' . getmypid();

$countClients = static function (Redis $redis) use ($clientName): int {
    // Match the full field so Redis's lib-name field is not counted.
    return preg_match_all(
        '/(?:^| )name=' . preg_quote($clientName, '/') . '(?: |$)/m',
        $redis->rawCommand('CLIENT', 'LIST')
    );
};

$waitForClients = static function (Redis $redis, int $expected) use ($countClients): void {
    $deadline = microtime(true) + 1;
    do {
        $count = $countClients($redis);
        if ($count === $expected) {
            return;
        }
        Co::sleep(0.001);
    } while (microtime(true) < $deadline);
    Assert::same($count, $expected, "Timed out waiting for {$expected} clients, found {$count}");
};

$timer_id = Swoole\Timer::tick(1000 / MAX_CONCURRENCY_MID, function () use (&$map, &$activeCallbacks, $clientName) {
    $activeCallbacks++;
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($redis->rawCommand('CLIENT', 'SETNAME', $clientName));
    Assert::assert($redis->set('foo', 'bar'));
    Assert::same($redis->get('foo'), 'bar');
    $map[] = $redis;
    $activeCallbacks--;
});

go(function () use ($timer_id, &$map, &$activeCallbacks, $countClients, $waitForClients) {
    Co::sleep(1);
    Swoole\Timer::clear($timer_id);
    $deadline = microtime(true) + 1;
    while ($activeCallbacks > 0 && microtime(true) < $deadline) {
        Co::sleep(0.001);
    }
    Assert::same($activeCallbacks, 0, "Timed out waiting for {$activeCallbacks} callbacks to finish");
    // A second unnamed client makes server-global counting fail; the observer alone would not.
    $unrelatedRedis = new Redis();
    $unrelatedRedis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::greaterThan(count($map), 0);
    $clientCount = $countClients($redis);
    Assert::same($clientCount, count($map), "Expected " . count($map) . " retained clients, found {$clientCount}");
    $map = []; // destruct
    $waitForClients($redis, 0);
    echo "DONE\n";
});

?>
--EXPECT--
DONE
