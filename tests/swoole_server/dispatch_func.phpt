--TEST--
swoole_server: dispatch_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_UDP);
            assert($client->connect('127.0.0.1', $pm->getFreePort()));
            assert($client->send($data = get_safe_random()));
            Assert::eq($data, $client->recv());
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

    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set([
        'worker_num' => rand(4, 8),
        'log_file' => '/dev/null',
        'dispatch_func' => 'dispatch_packet'
    ]);
    $server->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $server->on('packet', function (Swoole\Server $server, $data, $client) {
        $fd = unpack('L', pack('N', ip2long($client['address'])))[1];
        Assert::eq($fd % $server->setting['worker_num'], $server->worker_id);
        $server->sendto($client['address'], $client['port'], $data);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
