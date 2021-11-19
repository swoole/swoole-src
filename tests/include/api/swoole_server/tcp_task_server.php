<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
$host = isset($argv[1]) ? $argv[1] : TCP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : TCP_SERVER_PORT;
$server = new TcpServer($host, $port);
$server->start();

class TcpServer
{
    public $swooleServer;

    public function __construct($host, $port)
    {
        echo "swoole_server host:$host, port:$port\n";
        $this->swooleServer = new Swoole\Server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            "pipe_buffer_size" => 1024 * 1024 * 1024,
            'dispatch_mode' => 3,
            'open_tcp_nodelay' => 1,
            'open_cpu_affinity' => 1,
            //'daemonize' => 1,
            'reactor_num' => 2,
            'worker_num' => 4,
			'task_worker_num' => 8,
            'max_request' => 100000,
			'log_file' => '/tmp/swoole_server.log',
        ]);
    }

    public function start()
    {
        $this->swooleServer->on('start', [$this, 'onStart']);
        $this->swooleServer->on('shutdown', [$this, 'onShutdown']);

        $this->swooleServer->on('workerStart', [$this, 'onWorkerStart']);
        $this->swooleServer->on('workerStop', [$this, 'onWorkerStop']);
        $this->swooleServer->on('workerError', [$this, 'onWorkerError']);

        $this->swooleServer->on('connect', [$this, 'onConnect']);
        $this->swooleServer->on('receive', [$this, 'onReceive']);
        $this->swooleServer->on('task', [$this, 'onTask']);
        $this->swooleServer->on('finish', [$this, 'onFinish']);

        $this->swooleServer->on('close', [$this, 'onClose']);

        $this->swooleServer->start();
    }

    public function onConnect()
    {
	    debug_log("connecting ......");
    }

    public function onClose()
    {
        debug_log("closing .....");
    }

    public function onStart(Swoole\Server $swooleServer)
    {
        debug_log("swoole_server starting .....");
    }

    public function onShutdown(Swoole\Server $swooleServer)
    {
        debug_log("swoole_server shutdown .....");
    }

    public function onWorkerStart(Swoole\Server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
        if ($workerId == 0) {
            //Swoole\Timer::after(5000, function () {
            //    $this->swooleServer->shutdown();
            //});
        }
    }

    public function onWorkerStop(Swoole\Server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(Swoole\Server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onReceive(Swoole\Server $swooleServer, $fd, $fromId, $data)
    {
        //echo "swoole_server receive data: $data\n";
		$param = array(
			'fd' => $fd,
			'data' => $data,
		);
		$swooleServer->task(json_encode($param));
		//echo "send data to task worker.\n";
	}

    public function onTask(Swoole\Server $swooleServer, $task_id, $fromId, $data)
    {
        $task_data = json_decode($data, true);
        $swooleServer->finish($task_data);
    }

    public function onFinish(Swoole\Server $swooleServer, $worker_task_id, $task_data)
    {
        $swooleServer->send($task_data['fd'], "OK");
    }
}
