<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


if (pcntl_fork() === 0) {
    suicide(1000);
    exit();
}


if (pcntl_fork() === 0) {
    suicide(1000);
    exit();
}


if (pcntl_fork() === 0) {
    suicide(1000);


    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    /** @noinspection PhpVoidFunctionResultUsedInspection */
    assert($cli->set([
        "socket_buffer_size" => 1024,
    ]));

    $cli->on("connect", function(swoole_client $cli) {
        swoole_timer_clear($cli->timeo_id);
        assert($cli->isConnected() === true);
        $cli->send(str_repeat("\0", 1024));
    });

    $cli->on("receive", function(swoole_client $cli, $data){
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
        $cli->send(str_repeat("\0", $recv_len));
    });

    $cli->on("error", function(swoole_client $cli) {
        swoole_timer_clear($cli->timeo_id);
        debug_log("error");
    });

    $cli->on("close", function(swoole_client $cli) {
        swoole_timer_clear($cli->timeo_id);
        debug_log("close");
    });

    $cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
    $cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
        debug_log("connect timeout");
        $cli->close();
        assert($cli->isConnected() === false);
    });
    exit();
}

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
            "buffer_output_size" => 1024 * 1024 * 1024, // 输出限制
            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,


            // 'log_file' => __DIR__ . '/manager_process_exit.log',
            'daemonize' => 0,
            'worker_num' => 2,
            'max_request' => 100000,
            'reactor_num' => 1,
            // 'package_max_length' => 1024 * 1024 * 2
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
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
        $swooleServer->send($fd, str_repeat("\0", $recv_len));
    }
}