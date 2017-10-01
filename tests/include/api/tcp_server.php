<?php
$serv = new \swoole_server('127.0.0.1', 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);
$serv->set([
//            'log_file' => __DIR__ . '/simple_server.log',
    'dispatch_mode' => 2,
    'daemonize' => 0,
    'worker_num' => 1,
]);

$serv->on('workerStart', function (\swoole_server $serv)
{
    /**
     * @var $pm ProcessManager
     */
    global $pm;
    $pm->wakeup();
});

$serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
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
