--TEST--
swoole_server: bug Github#2308
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 64;
const M = 512;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $server = new \Swoole\Server('0.0.0.0', 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $server->set([
        'worker_num' => 4,
        'log_file' => '/dev/null',
        'enable_coroutine' => false,
    ]);
    $server->on('start', function () {
        \Swoole\Coroutine::create(function () {
            $redis = new \Swoole\Coroutine\Redis();
            $redis->connect('127.0.0.1', 6379);
            while (true) {
                $msg = $redis->subscribe(['task']);
            }
        });
    });
    $server->on('workerStart', function ($server) {
        $server->after(1000, function () use ($server) {
            $server->stop();
        });
    });
    $server->on('Receive',function (swoole_server $server, int $fd, int $reactor_id, string $data){

    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Swoole\Coroutine::create(): Unable to use async-io in manager process in %s on line %d
