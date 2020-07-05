--TEST--
swoole_server/task: scheduler warning
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    $client->send("ping");
    $client->send("ping");
    sleep(2);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new Server("127.0.0.1", $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

    $serv->set([
        'task_worker_num' => 1,
        'log_level' => SWOOLE_LOG_NOTICE,
    ]);

    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        if ($serv->taskworker) {
            $pm->wakeup();
        }
    });

    $serv->on('Packet', function (Server $serv, string $data, array $clientInfo) {
        $serv->task($data);
    });

    $serv->on('Task', function (Server $serv, $task_id, int  $from_id, string $data) {
        sleep(1);
    });

    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	WARNING	swServer_master_onTimer (ERRNO %d): No idle task worker is available
