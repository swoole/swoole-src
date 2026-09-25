--TEST--
swoole_runtime: socket destruct close
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$activeCallbacks = 0;
$clientName = 'swoole-runtime-destruct-' . getmypid();

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

$timer_id = Swoole\Timer::tick(1000 / MAX_CONCURRENCY_MID, function () use (&$activeCallbacks, $clientName) {
    $activeCallbacks++;
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($redis->rawCommand('CLIENT', 'SETNAME', $clientName));
    Assert::assert($redis->set('foo', 'bar'));
    Assert::same($redis->get('foo'), 'bar');
    $activeCallbacks--;
});

go(function () use ($timer_id, &$activeCallbacks, $countClients, $waitForClients, $clientName) {
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
    $waitForClients($redis, 0);
    $probe = new Redis();
    $probe->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($probe->rawCommand('CLIENT', 'SETNAME', $clientName));
    Assert::same($countClients($redis), 1, 'The named-client matcher did not find the probe');
    echo "DONE\n";
});

?>
--EXPECT--
DONE
