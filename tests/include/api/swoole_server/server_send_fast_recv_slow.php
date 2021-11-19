<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


if (pcntl_fork() === 0) {
    suicide(3000);


    $cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    /** @noinspection PhpVoidFunctionResultUsedInspection */
    assert($cli->set([
        "socket_buffer_size" => 1,
    ]));

    $cli->on("connect", function(Swoole\Client $cli) {
        Swoole\Timer::clear($cli->timeo_id);

        // TODO getSocket BUG
        // assert(is_resource($cli->getSocket()));
        /*
        $cli->getSocket();
        // Warning: swoole_client_async::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].
        $cli->getSocket();
         */


        Assert::true($cli->isConnected());
        $cli->send(str_repeat("\0", 1024));
        // $cli->sendfile(__DIR__.'/test.txt');
    });

    $cli->on("receive", function(Swoole\Client $cli, $data){
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
        $cli->send(str_repeat("\0", 1024));
    });

    $cli->on("error", function(Swoole\Client $cli) {
        Swoole\Timer::clear($cli->timeo_id);
        debug_log("error");
    });

    $cli->on("close", function(Swoole\Client $cli) {
        Swoole\Timer::clear($cli->timeo_id);
        debug_log("close");
    });

    $cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
    $cli->timeo_id = Swoole\Timer::after(1000, function() use($cli) {
        debug_log("connect timeout");
        $cli->close();
        Assert::false($cli->isConnected());
    });

    exit();
}


(new TcpServer())->start();

class TcpServer
{
    /**
     * @var Swoole\Server
     */
    public $swooleServer;

    public function __construct()
    {
        $this->swooleServer = new Swoole\Server(TCP_SERVER_HOST, TCP_SERVER_PORT, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            "output_buffer_size" => 1024 * 1024 * 1024, // 输出限制
            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,

            // 'log_file' => __DIR__ . '/send_fast_recv_slow.log',
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
        $recv_len = strlen($data);
        debug_log("receive: len $recv_len");
        $swooleServer->send($fd, str_repeat("\0", $recv_len));
    }
}
