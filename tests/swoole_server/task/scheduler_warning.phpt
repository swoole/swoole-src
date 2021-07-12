--TEST--
swoole_server/task: scheduler warning
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

const N = 3;
const LOG_FILE =  __DIR__.'/test.log';

$counter = new Swoole\Atomic(0);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort(), 2)) {
        exit("connect failed\n");
    }
    $client->send("ping");
    echo $client->recv();
    sleep(2);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $counter) {
    $serv = new Server("127.0.0.1", $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

    $serv->set([
        'worker_num' => 1,
        'task_worker_num' => 2,
        'log_file' => LOG_FILE,
        'log_level' => SWOOLE_LOG_NOTICE,
    ]);

    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        if ($serv->taskworker) {
            $pm->wakeup();
        }
    });

    $serv->on('Packet', function (Server $serv, string $data, array $clientInfo) {
        $n = N;
        while ($n--) {
            $serv->task(['data' => $data, 'client' => $clientInfo]);
            usleep(10000);
        }
    });

    $serv->on('Task', function (Server $serv, $taskId, int $workerId, $data) use ($pm, $counter) {
        static $sleep = false;
        if (!$sleep) {
            $sleep = true;
            sleep(1);
        }
        if ($counter->add() == N) {
            $serv->sendto($data['client']['address'], $data['client']['port'], "DONE\n");
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();

echo file_get_contents(LOG_FILE);
unlink(LOG_FILE);
?>
--EXPECTF--
DONE
[%s]	WARNING	Server::timer_callback() (ERRNO %d): No idle task worker is available
