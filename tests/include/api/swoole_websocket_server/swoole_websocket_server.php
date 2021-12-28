<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

class WebSocketServer
{
    /**
     * @var Swoole\WebSocket\Server
     */
    public $webSocketServ;

    public function __construct($host = WEBSOCKET_SERVER_HOST, $port = WEBSOCKET_SERVER_PORT)
    {
        $this->webSocketServ = new Swoole\WebSocket\Server($host, $port);

        $this->webSocketServ->set([
            // 输出限制
            "output_buffer_size" => 1024 * 1024 * 1024,

            "max_connection" => 10240,
            "pipe_buffer_size" => 1024 * 1024 * 1024,

            // 'enable_port_reuse' => true,
            'user' => 'www-data',
            'group' => 'www-data',

            // 'log_file' => __DIR__.'/swoole.log',
            'open_tcp_nodelay' => 1,
            'open_cpu_affinity' => 1,
            'daemonize' => 0,
            'reactor_num' => 1,
            'worker_num' => 2,
            'max_request' => 100000,
        ]);

    }

    public function start()
    {
        $this->webSocketServ->on('start', [$this, 'onStart']);
        $this->webSocketServ->on('shutdown', [$this, 'onShutdown']);

        $this->webSocketServ->on('workerStart', [$this, 'onWorkerStart']);
        $this->webSocketServ->on('workerStop', [$this, 'onWorkerStop']);
        $this->webSocketServ->on('workerError', [$this, 'onWorkerError']);

        $this->webSocketServ->on('connect', [$this, 'onConnect']);
        $this->webSocketServ->on('request', [$this, 'onRequest']);

        $this->webSocketServ->on('open', [$this, 'onOpen']);
        $this->webSocketServ->on('message', [$this, 'onMessage']);

        $this->webSocketServ->on('close', [$this, 'onClose']);

        $this->webSocketServ->start();
    }

    public function onConnect()
    {
        debug_log("connecting ......");
    }

    public function onClose()
    {
        debug_log("closing .....");
    }

    public function onStart(Swoole\WebSocket\Server $swooleServer)
    {
        debug_log("swoole_server starting .....");
    }

    public function onShutdown(Swoole\WebSocket\Server $swooleServer)
    {
        debug_log("swoole_server shutdown .....");
    }

    public function onWorkerStart(Swoole\WebSocket\Server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(Swoole\WebSocket\Server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(Swoole\WebSocket\Server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onRequest(\Swoole\Http\Request $request, \Swoole\Http\Response $response)
    {
        $response->end("Hello World!");
    }

    public function onOpen(Swoole\WebSocket\Server  $server, $request)
    {
        debug_log("{$request->fd} opened");
    }

    public function onMessage(Swoole\WebSocket\Server  $server, $frame)
    {
        $server->push($frame->fd, "SUCCESS");
    }
}

$host = isset($argv[1]) ? $argv[1] : WEBSOCKET_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : WEBSOCKET_SERVER_PORT;

$wsServer = new WebSocketServer($host, $port);
$wsServer->start();
