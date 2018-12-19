--TEST--
swoole_server_port: heartbeat
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm)
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cli->connect('127.0.0.1', $pm->getFreePort(0));
        for ($i = 0; $i < 2; ++$i) {
            $cli->send('hello');
            $data = $cli->recv();
            if ($data != 'ok') {
                echo "ERROR\n";
            }
            co::sleep(2);
        }
        co::sleep(3);
        $cli->send('hello');
        $data = $cli->recv();
        if ($data == 'ok') {
            echo "ERROR\n";
        }
    });

    go(function () use ($pm)
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cli->connect('127.0.0.1', $pm->getFreePort(1));
        for ($i = 0; $i < 2; ++$i) {
            $cli->send('hello');
            $data = $cli->recv();
            if ($data != 'ok') {
                echo "ERROR\n";
            }
            co::sleep(2);
        }
        co::sleep(3);
        $cli->send('hello');
        $data = $cli->recv();
        if ($data == 'ok') {
            echo "ERROR\n";
        } else {
            echo "OK";
        }
    });

    swoole_event_wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $server = new swoole_server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->set([
        'heartbeat_check_interval' => 1,
        'heartbeat_idle_time' => 3
    ]);
    $server->on('receive', function ($server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });

    $port2 = $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    // $port2->set([
        // 'heartbeat_check_interval' => 1,
        // 'heartbeat_idle_time' => 5
    // ]);
    $port2->on('receive', function ($server, $fd, $reactorId, $data) {
        $server->send($fd, 'ok');
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
