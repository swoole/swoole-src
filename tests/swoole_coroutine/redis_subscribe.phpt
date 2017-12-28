--TEST--
swoole_coroutine: redis subscribe
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc";
if (!class_exists('redis', false)) {
    exit("SKIP");
}
?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

use Swoole\Coroutine as co;

const N = 100;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) {
    $redis = new redis;
    $redis->connect('127.0.0.1', 6379);
    for ($i = 0; $i < N; $i++)
    {
        $redis->publish('test', 'hello-' . $i);
    }
};

$pm->childFunc = function () use ($pm) {
    co::create(function () use ($pm) {
        $redis = new co\Redis();
        $redis->connect('127.0.0.1', 6379);
        $pm->wakeup();
        for ($i = 0; $i < N; $i++)
        {
            $val = $redis->subscribe(['test']);
            assert($val and count($val) > 1);
        }
        $redis->close();
        echo "OK\n";
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
