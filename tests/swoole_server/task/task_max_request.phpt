--TEST--
swoole_server/task: task_max_request
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const N = 4000;

use Swoole\Server;
use Swoole\Atomic;

$counter1 = new Atomic(); // onTask
$counter2 = new Atomic(); // onFinish
$counter3 = new Atomic(); // task num

$process = new Swoole\Process(function() {

    $serv = new Server('127.0.0.1', get_one_free_port());
    $serv->set([
        "worker_num" => 1,
        'task_max_request' => 200,
        'task_worker_num' => 4,
        'log_file' => TEST_LOG_FILE,
    ]);

    $serv->on("WorkerStart", function (Server $serv, $worker_id)
    {
        if (!$serv->taskworker) {
            for($i = 0; $i< N; $i++) {
                $serv->task(array('type' => 'php', 'data' => RandStr::gen(100)));
            }
        } else {
            //Task 进程启动数量
            global $counter3;
            $counter3->add(1);
        }
    });

    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data)
    {
        $serv->send($fd, "Server: $data");
    });

    $serv->on('Task', function ($swooleServer, $task_id, $workerId, $data)
    {
        global $counter1;
        $counter1->add(1);
        return json_encode($data);
    });

    $serv->on('Finish', function (Server $swooleServer, $workerId, $task_data)
    {
        global $counter2;
        $counter2->add(1);
        if ($counter2->get() == N) {
            $swooleServer->shutdown();
        }
    });

    $serv->start();
},false, false);
$process->start();

Swoole\Process::wait();
Assert::same($counter1->get(), 4000);
Assert::same($counter2->get(), 4000);
Assert::assert($counter3->get() > 15);
echo "DONE\n";
?>
--EXPECT--
DONE
