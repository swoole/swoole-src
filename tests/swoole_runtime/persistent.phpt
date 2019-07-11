--TEST--
swoole_runtime: socket persistent then destruct
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$redis = new Redis();
$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
$redis->rawCommand('CLIENT', 'KILL', 'TYPE', 'normal');
$redis->close();
usleep(100);

Swoole\Runtime::enableCoroutine();

$map = [];

$timer_id = Swoole\Timer::tick(1000 / MAX_CONCURRENCY_MID, function () use (&$map) {
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($redis->set('foo', 'bar'));
    Assert::same($redis->get('foo'), 'bar');
    $map[] = $redis;
});

go(function () use ($timer_id, &$map) {
    co::sleep(1);
    Swoole\Timer::clear($timer_id);
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $info = (array)$redis->info('clients');
    phpt_var_dump($info);
    Assert::same($info['connected_clients'], count($map) + 1, var_dump_return($info));
    $map = []; // destruct
    usleep(100);
    $info = (array)$redis->info('clients');
    phpt_var_dump($info);
    Assert::same($info['connected_clients'], 1, var_dump_return($info));
    echo "DONE\n";
});

?>
--EXPECT--
DONE
