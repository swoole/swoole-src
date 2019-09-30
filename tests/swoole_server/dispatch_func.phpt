--TEST--
swoole_server: dispatch_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip('not support ZTS', ZEND_THREAD_SAFE);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_UDP);
            Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
            Assert::assert($client->send($data = get_safe_random()));
            Assert::same($client->recv(), $data);
        });
    }
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {

    function dispatch_packet($server, $fd, $type)
    {
        return $fd % $server->setting['worker_num'];
    }

    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set([
        'worker_num' => rand(4, 8),
        'log_file' => '/dev/null',
        'dispatch_func' => 'dispatch_packet'
    ]);
    $server->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $server->on('packet', function (Server $server, $data, $client) {
        $fd = unpack('L', pack('N', ip2long($client['address'])))[1];
        Assert::same($fd % $server->setting['worker_num'], $server->worker_id);
        $server->sendto($client['address'], $client['port'], $data);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
