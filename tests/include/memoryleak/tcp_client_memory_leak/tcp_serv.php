<?php


class TcpServer
{
    /**
     * @var \swoole_server
     */
    public $swooleServer;

    public function __construct()
    {
        $this->swooleServer = new \swoole_server("127.0.0.1", 9001, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            // "buffer_output_size" => 1024 * 1024 * 1024, // 输出限制

            'log_file' => __DIR__ . '/swoole.log',
            'max_connection'    => 10240,
            'pipe_buffer_size'  => 1024 * 1024 * 1024,

            'dispatch_mode'     => 3,
            'open_tcp_nodelay'  => 1,
            'open_cpu_affinity' => 1,
            'daemonize'         => 0,
            'reactor_num'       => 1,
            'worker_num'        => 2,
            'max_request'       => 100000,
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
//        print("connecting ......");
    }

    public function onClose()
    {
//        print("closing .....");
    }

    public function onStart(swoole_server $swooleServer)
    {
//        print("swoole_server starting .....");
    }

    public function onShutdown(swoole_server $swooleServer)
    {
//        print("swoole_server shutdown .....");
    }

    public function onWorkerStart(swoole_server $swooleServer, $workerId)
    {
//        print("worker #$workerId starting .....");
    }

    public function onWorkerStop(swoole_server $swooleServer, $workerId)
    {
//        print("worker #$workerId stopping ....");
    }

    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
//        print("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onReceive(swoole_server $swooleServer, $fd, $fromId, $data)
    {
        static $i;
        if ($i > 20000)
        {
            $swooleServer->close($fd);
            $swooleServer->shutdown();
            @unlink(__DIR__ . '/swoole.log');
        }
        else
        {
            $swooleServer->send($fd, $data);
        }
        $i++;
    }
}

(new TcpServer())->start();
