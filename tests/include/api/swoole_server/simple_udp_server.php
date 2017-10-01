<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

(new UdpServer())->start();

class UdpServer
{
    public $swooleServer;

    public function __construct()
    {
	    $this->swooleServer = new \swoole_server(UDP_SERVER_HOST, UDP_SERVER_PORT, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
        $this->swooleServer->set([
            "max_connection" => 1000,
            'dispatch_mode' => 3,
            'daemonize' => 0,
            'reactor_num' => 4,
            'worker_num' => 8,
            'max_request' => 1000,
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
        $this->swooleServer->on('Packet',  [$this, 'onPacket']);
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
        swoole_timer_after(3000, function() {
            $this->swooleServer->shutdown();
        });
    }

    public function onWorkerStop(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    //UDP: 收到数据帧事件
    public function onPacket(swoole_server $swooleServer, $data, $clientInfo)
    {
        if (trim($data) == 'shutdown')
        {
            $swooleServer->shutdown();
            return;
        }
        //echo "clientInfo: $clientInfo, receive: $data\n";
        $swooleServer->sendto($clientInfo['address'], $clientInfo['port'], $data);
    }
}
