<?php

#This script is forked from db_pool.php
#
#u can test like this,
#
#/usr/local/php/bin/php bench.php -n 1000 -c 100 -s tcp://127.0.0.1:9508 -f short_tcp / long_tcp
#
#

define("SERVER_RELOAD", 'U0VSVkVSX1JFTE9BRAo=');

if(!extension_loaded('swoole')){
    throw new Exception("install swoole extension, pecl install swoole");
}

if(!extension_loaded('redis')) {
	throw new Exception("install redis extension, pecl install redis");
}

$serv = new swoole_server("0.0.0.0", 9508);

$serv->set(array(
    'worker_num' => 4,//base on you cpu nums
    'task_worker_num' => 4,//better equal to worker_num, anyway you can define your own
	'heartbeat_check_interval' => 5,
	'heartbeat_idle_time' => 5,
    'open_cpu_affinity' => 1,
	'open_eof_check'  => 1,
	'package_eof'   => "\r\n\r\n",
	'package_max_length' => 1024 * 16,
	//'daemonize' => 1
));

function onStart($serv) {
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function onReceive($serv, $fd, $from_id, $key)
{
	$key = trim($key);
    if($key === SERVER_RELOAD) { // check if this is a reload cmd
        $ret = $serv->reload($serv);
        ($ret === true) ? $serv->send($fd, "reload success\n") : $serv->send($fd, "reload fail\n");
    }else {
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
}

function onTask($serv, $task_id, $from_id, $key)
{
    static $redis = null;
    if ($redis == null) {
        $redis = new Redis();
        $redis->pconnect("127.0.0.1", 6379);
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

$serv->on('Start', 'onStart');
$serv->on('Receive', 'onReceive');
$serv->on('Task', 'onTask');
$serv->on('Finish', 'onFinish');
$serv->start();

