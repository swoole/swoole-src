--TEST--
swoole_server: task_max_request

--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

const N = 4000;

$counter1 = new swoole_atomic();
$counter2 = new swoole_atomic();
$counter3 = new swoole_atomic();

swoole_unittest_fork(function() {

    $serv = new \swoole_server("127.0.0.1", 9503);
    $serv->set([
        "worker_num" => 1,
        'task_max_request' => 200,
        'task_worker_num' => 4,
        'log_file' => '/dev/null',
    ]);

    $serv->on("WorkerStart", function (\swoole_server $serv)
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

    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {
        $serv->send($fd, "Server: $data");
    });

    $serv->on('Task', function ($swooleServer, $task_id, $workerId, $data)
    {
        global $counter1;
        $counter1->add(1);
        return json_encode($data);
    });

    $serv->on('Finish', function (swoole_server $swooleServer, $workerId, $task_data)
    {
        global $counter2;
        $counter2->add(1);
        if ($counter2->get() == N) {
            $swooleServer->shutdown();
        }
    });

    $serv->start();
});

swoole_unittest_wait();
assert($counter1->get() == 4000);
assert($counter2->get() == 4000);
assert($counter2->get() > 15);
?>

--EXPECT--
