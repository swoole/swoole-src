--TEST--
swoole_server/task: task pack
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_function_not_exist('msg_get_queue');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
const MSGQ_KEY = 0x70001001;

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$result = new Swoole\Atomic(0);

$pm->parentFunc = function ($pid) use ($pm) {
    $task = new class(MSGQ_KEY, 0) {
        protected $queueId;
        protected $workerId;

        function __construct($key, $workerId) {
            $this->queueId = msg_get_queue($key);
            if ($this->queueId === false) {
                throw new \Swoole\Exception("msg_get_queue() failed.");
            }
            $this->workerId = $workerId;
        }

        function dispatch($data) {
            if (!msg_send($this->queueId, $this->workerId + 1, Swoole\Server\Task::pack($data), false)) {
                return false;
            } else {
                return true;
            }
        }
    };
    //数组
    $task->dispatch(array('data' => str_repeat('A', 1024), 'type' => 1));
    //大包
    $task->dispatch(array('data' => str_repeat('B', 1024 * 32), 'type' => 2));
    //普通字符串
    $task->dispatch(str_repeat('C', 512));
};

$pm->childFunc = function () use ($pm) {
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 1,
        'task_ipc_mode' => 3,
        'message_queue_key' => MSGQ_KEY,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {

    });
    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data) {
        global $result;
        switch ($task_id) {
            case 0:
                Assert::isArray($data);
                Assert::eq($data['type'], 1);
                Assert::length($data['data'], 1024);
                $result->add(1);
                break;
            case 1:
                Assert::isArray($data);
                Assert::eq($data['type'], 2);
                Assert::length($data['data'], 1024 * 32);
                $result->add(1);
                break;
            case 2:
                Assert::assert(is_string($data));
                Assert::length($data, 512);
                $result->add(1);
                $serv->shutdown();
                break;
            default:
                break;
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();

Assert::eq($result->get(), 3);
?>
--EXPECT--
