<?php
$serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
$serv->set([
//            'log_file' => __DIR__ . '/simple_server.log',
    'dispatch_mode' => 2,
    'daemonize' => 0,
    'worker_num' => 1,
]);

$serv->on('workerStart', function (Swoole\Server $serv)
{
    /**
     * @var $pm ProcessManager
     */
    global $pm;
    $pm->wakeup();
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data)
{
    if (trim($data) == 'shutdown')
    {
        $serv->shutdown();
        return;
    }
    $recv_len = strlen($data);
    $serv->send($fd, RandStr::gen($recv_len, RandStr::ALL));
});

$serv->start();
