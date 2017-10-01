<?php

function debug_log($str, $handle = STDERR)
{
    if ($handle === STDERR) {
        $tpl = "\033[31m[%d %s] %s\033[0m\n";
    } else {
        $tpl = "[%d %s] %s\n";
    }
    if (is_resource($handle)) {
        fprintf($handle, $tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    } else {
        printf($tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    }
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
        $this->swooleServer = new \swoole_server("127.0.0.1", 9001, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            // "buffer_output_size" => 1024 * 1024 * 1024, // 输出限制

            'max_connection'    => 10240,
            'pipe_buffer_size'  => 1024 * 1024 * 2,
//            'pipe_buffer_size'  => 1024,

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
        echo "close $fd\n";
//        var_dump($swooleServer->shutdown());
        // swoole_server 接受数据之后立马关闭连接
        var_dump($swooleServer->close($fd));
        // $swooleServer->send($fd, $data);
    }
}