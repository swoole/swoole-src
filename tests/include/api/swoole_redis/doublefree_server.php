<?php

(new FakeRedisServer())->start();

class FakeRedisServer
{
    public $swooleServer;

    public function __construct()
    {
        $this->swooleServer = new \swoole_server("0.0.0.0", 6379, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set(["worker_num" => 1]);
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

    public function onClose() {}
    public function onStart(swoole_server $swooleServer) {}
    public function onShutdown(swoole_server $swooleServer) {}
    public function onWorkerStart(swoole_server $swooleServer, $workerId) {}
    public function onWorkerStop(swoole_server $swooleServer, $workerId) {}
    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo) {}

    public function onConnect(swoole_server $swooleServer, $fd) {
        // $swooleServer->close($fd);
    }

    public function onReceive(swoole_server $swooleServer, $fd, $fromId, $data)
    {
        $swooleServer->send($fd, "\0");
        return;

        $swooleServer->send($fd, "$-1\r\n");
        echo $data;
        swoole_timer_after(1000, function() use($swooleServer, $fd) {
            $swooleServer->close($fd);
        });
    }
}
