<?php
#
#u can test like this,
#
#/usr/local/php/bin/php bench.php -n 1000 -c 100 -s tcp://127.0.0.1:9508 -f short_tcp

$serv = new swoole_server("0.0.0.0", 9508);

$serv->set(array(
    'worker_num' => 4,
    'task_worker_num' => 4,
	'heartbeat_check_interval' => 5,
	'heartbeat_idle_time' => 5,
    'open_cpu_affinity' => 1,
	//'daemonize' => 1
));

function onReceive($serv, $fd, $from_id, $key)
{
	$key = trim($key);
    $result = $serv->taskwait($key);
    if ($result !== false) {
        list($status, $data) = explode(':', $result, 2);
        if ($status == 'OK') {
            $serv->send($fd, $key . " : " . var_export(unserialize($data), true) . "\n");
        } else {
            $serv->send($fd, $data);
        }
        return;
    } else {
        $serv->send($fd, "Error. Task timeout\n");
    }
}

function onTask($serv, $task_id, $from_id, $key)
{
    static $redis = null;
    if ($redis == null) {
        $redis = new Redis();
        $redis->connect("127.0.0.1", 6379, 1);
        if (!$redis) {
            $redis = null;
            $serv->finish("ER: Init Redis Fail.");
            return;
        }
    }
    $data = $redis->get($key);
    if ($data === false) {
        $serv->finish("ER: Get Data Fail.");
        return;
    }
    $serv->finish("OK:" . serialize($data));
}

function onFinish($serv, $data)
{
    echo "AsyncTask Finish:Connect.PID=" . posix_getpid() . PHP_EOL;
}

$serv->on('Receive', 'onReceive');
$serv->on('Task', 'onTask');
$serv->on('Finish', 'onFinish');
$serv->start();
