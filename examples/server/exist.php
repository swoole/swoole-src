<?php
class G
{
	static $serv;
    private static $buffers = array();

    /**
     * @param $fd
     * @return swoole_buffer
     */
    static function getBuffer($fd, $create = true)
    {
        if (!isset(self::$buffers[$fd]))
        {
            if (!$create)
            {
                return false;
            }
            self::$buffers[$fd] = new swoole_buffer(1024 * 128);
        }
        return self::$buffers[$fd];
    }
}

$config = array(
   //'worker_num' => 4,
    //'open_eof_check' => true,
    //'package_eof' => "\r\n",
//   'task_ipc_mode'   => 2,
   'task_worker_num' => 2,
   'user' => 'www',
   'group' => 'www',
   'chroot' => '/opt/tmp',
    //'task_ipc_mode' => 1,
    //'dispatch_mode' => 1,
    //'log_file' => '/tmp/swoole.log',
   'heartbeat_check_interval' => 300,
   'heartbeat_idle_time'      => 300,
    // open_cpu_affinity => 1,
    //'cpu_affinity_ignore' =>array(0,1)//如果你的网卡2个队列（或者没有多队列那么默认是cpu0来处理中断）,并且绑定了core 0和core 1,那么可以通过这个设置避免swoole的线程或者进程绑定到这2个core，防止cpu0，1被耗光而造成的丢包
);

if (isset($argv[1]) and $argv[1] == 'daemon') {
	$config['daemonize'] = true;
} else {
	$config['daemonize'] = false;
}

//$mode = SWOOLE_BASE;
$mode = SWOOLE_PROCESS;

$serv = new swoole_server("0.0.0.0", 9501, $mode);
$serv->set($config);
/**
 * 使用类的静态属性，可以直接访问
 */
G::$serv = $serv;

function my_onStart(swoole_server $serv)
{
    global $argv;
    swoole_set_process_name("php {$argv[0]}: master");
    echo "MasterPid={$serv->master_pid}|Manager_pid={$serv->manager_pid}\n";
    echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
}

function my_log($msg)
{
    echo $msg.PHP_EOL;
}

function my_onShutdown($serv)
{
    echo "Server: onShutdown\n";
}

function my_onClose($serv, $fd, $from_id)
{
    my_log("Worker#{$serv->worker_pid} Client[$fd@$from_id]: fd=$fd is closed");
    $buffer = G::getBuffer($fd);
    if ($buffer)
    {
        $buffer->clear();
    }
    if($serv->exist($fd)) {
        echo 'FD[' . $fd . '] exist' . PHP_EOL;
    } else {
        echo 'FD[' . $fd . '] not exist' . PHP_EOL;
    }
}

function my_onConnect(swoole_server $serv, $fd, $from_id)
{
    if($serv->exist($fd)) {
        echo 'FD[' . $fd . '] exist' . PHP_EOL;
    } else {
        echo 'FD[' . $fd . '] not exist' . PHP_EOL;
    }
}

function my_onReceive(swoole_server $serv, $fd, $from_id, $data)
{
    if($serv->exist($fd)) {
        echo 'FD[' . $fd . '] exist' . PHP_EOL;
    } else {
        echo 'FD[' . $fd . '] not exist' . PHP_EOL;
    }
    $serv->task($data . '-' . $fd);
}

function my_onTask(swoole_server $serv, $task_id, $from_id, $data)
{
    list($str, $fd) = explode('-', $data);
    if($serv->exist($fd)) {
        echo 'FD[' . $fd . '] exist' . PHP_EOL ;
    } else {
        echo 'FD[' . $fd . '] not exist' . PHP_EOL;
    }
    echo "Task[PID=".$serv->worker_pid."]: task_id=$task_id.".PHP_EOL;
    return $data;
}

function my_onFinish(swoole_server $serv, $task_id, $data)
{
	list($str, $fd) = explode('-', $data);
    $serv->send($fd, 'Send Data To FD[' . $fd . ']');
    echo "Task Finish: result=" . $data . ". PID=" . $serv->worker_pid.PHP_EOL;
}

$serv->on('Start', 'my_onStart');
$serv->on('Connect', 'my_onConnect');
$serv->on('Receive', 'my_onReceive');
$serv->on('Close', 'my_onClose');
$serv->on('Shutdown', 'my_onShutdown');
$serv->on('Task', 'my_onTask');
$serv->on('Finish', 'my_onFinish');
$serv->on('ManagerStart', function($serv) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: manager");
});
$serv->start();
