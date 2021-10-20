--TEST--
swoole_server: bug Github#2308
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('0.0.0.0', 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $server->set([
        'worker_num' => MAX_PROCESS_NUM,
        'log_file' => '/dev/null',
        'enable_coroutine' => false,
    ]);
    $server->on('start', function () {
        \Swoole\Coroutine::create(function () {
            $redis = new \Swoole\Coroutine\Redis();
            $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
            $ret = $redis->set('foo', 'bar');
            Assert::assert($ret);
            $ret = $redis->get('foo');
            Assert::same($ret, 'bar');
        });
    });
    $server->on('workerStart', function ($server) {
        $server->after(1000, function () use ($server) {
            $server->stop();
        });
    });
    $server->on('Receive', function (Server $server, int $fd, int $reactor_id, string $data) {
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
