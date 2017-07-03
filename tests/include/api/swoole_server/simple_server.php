<?php

require_once __DIR__ . "/../../../include/bootstrap.php";
/*
if (pcntl_fork() === 0) {
    require_once __DIR__ . "/../swoole_client_async/simple_client.php";
    exit();
}*/

(new TcpServer())->start();

class TcpServer
{
    /**
     * @var \swoole_server
     */
    public $swooleServer;

    public function __construct()
    {
	$this->swooleServer = new \swoole_server(TCP_SERVER_HOST, TCP_SERVER_PORT, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            // "buffer_output_size" => 1024 * 1024 * 1024, // 输出限制
            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,

            // 'enable_port_reuse' => true,
            // 'user' => 'www-data',
            // 'group' => 'www-data',

//            'log_file' => __DIR__ . '/simple_server.log',
            'dispatch_mode' => 2,
            'open_tcp_nodelay' => 1,
            'open_cpu_affinity' => 1,
            'daemonize' => 0,
            'reactor_num' => 1,
            'worker_num' => 1,
            'max_request' => 100000,
            // 'package_max_length' => 1024 * 1024 * 2
            /*
            'open_length_check' => 1,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 0,
            'open_nova_protocol' => 1,
            */
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

    public function onStart(swoole_server $swooleServer)
    {
        debug_log("swoole_server starting .....");
    }

    public function onShutdown(swoole_server $swooleServer)
    {
        debug_log("swoole_server shutdown .....");
    }

    public function onWorkerStart(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onReceive(swoole_server $swooleServer, $fd, $fromId, $data)
    {
        if (trim($data) == 'shutdown')
        {
            $swooleServer->shutdown();
            return;
        }
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
	    $swooleServer->send($fd, RandStr::gen($recv_len, RandStr::ALL));
        // $swooleServer->close($fd);
    }
}
