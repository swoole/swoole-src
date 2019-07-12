--TEST--
swoole_runtime: socket destruct close
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

$timer_id = Swoole\Timer::tick(1000 / MAX_CONCURRENCY_MID, function () {
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    Assert::assert($redis->set('foo', 'bar'));
    Assert::same($redis->get('foo'), 'bar');
});

go(function () use ($timer_id) {
    co::sleep(1);
    Swoole\Timer::clear($timer_id);
    $redis = new Redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    $info = (array) $redis->info('clients');
    phpt_var_dump($info);
    Assert::same($info['connected_clients'], 1, var_dump_return($info));
    echo "DONE\n";
});

?>
--EXPECT--
DONE
