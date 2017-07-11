<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

class WebSocketServer
{
    /**
     * @var \swoole_websocket_server
     */
    public $webSocketServ;

    public function __construct($host = WEBSOCKET_SERVER_HOST, $port = WEBSOCKET_SERVER_PORT)
    {
        $this->webSocketServ = new \swoole_websocket_server($host, $port);

        $this->webSocketServ->set([
            // 输出限制
            "buffer_output_size" => 1024 * 1024 * 1024,

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

        $sock = $this->webSocketServ->getSocket();
        if (!socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1)) {
            echo 'Unable to set option on socket: '. socket_strerror(socket_last_error()) . PHP_EOL;
        }

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

    public function onStart(\swoole_websocket_server $swooleServer)
    {
        debug_log("swoole_server starting .....");
    }

    public function onShutdown(\swoole_websocket_server $swooleServer)
    {
        debug_log("swoole_server shutdown .....");
    }

    public function onWorkerStart(\swoole_websocket_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(\swoole_websocket_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(\swoole_websocket_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onRequest(\swoole_http_request $request, \swoole_http_response $response)
    {
        $response->end("Hello World!");
    }

    public function onOpen(swoole_websocket_server $server, $request)
    {
        debug_log("{$request->fd} opened");
    }

    public function onMessage(swoole_websocket_server $server, $frame)
    {
        $server->push($frame->fd, "SUCCESS");
    }
}

$host = isset($argv[1]) ? $argv[1] : WEBSOCKET_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : WEBSOCKET_SERVER_PORT;

$wsServer = new WebSocketServer($host, $port);
$wsServer->start();