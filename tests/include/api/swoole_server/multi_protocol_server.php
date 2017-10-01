<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

//(new OpcodeServer("127.0.0.1", 9999, 9998, 9997))->start(PHP_INT_MAX);

$host = isset($argv[1]) ? $argv[1] : null;
$port = isset($argv[2]) ? $argv[2] : null;
$port1 = isset($argv[3]) ? $argv[3] : null;
$port2 = isset($argv[4]) ? $argv[4] : null;

(new OpcodeServer($host, $port, $port1, $port2))->start();

class OpcodeServer
{
    /**
     * @var \swoole_server
     */
    public $swooleServer;

    public function __construct($host, $port, $port1, $port2)
    {
	    $this->swooleServer = new \swoole_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            'dispatch_mode' => 3,
            'worker_num' => 2,

            'open_eof_split' => true,
            'package_eof' => "\r\n",
        ]);

        $this->swooleServer->on("receive", function(\swoole_server $server, $fd, $fromReactorId, $recv) use($port) {
            assert(intval($recv) === $port);
            $r = $server->send($fd, opcode_encode("return", $port));
            assert($r !== false);
        });

        $serv1 = $this->swooleServer->listen(TCP_SERVER_HOST, $port1, SWOOLE_SOCK_TCP);
        assert($serv1 !== false);


        $serv1->set([
           'open_eof_split' => true,
           'package_eof' => "\r",
        ]);

        $serv1->on("receive", function(\swoole_server $server, $fd, $fromReactorId, $recv) use($port1) {
            assert(intval($recv) === $port1);
            $r = $server->send($fd, opcode_encode("return", $port1));
            assert($r !== false);
        });


        $serv2 = $this->swooleServer->listen(TCP_SERVER_HOST, $port2, SWOOLE_SOCK_TCP);
        assert($serv2 !== false);

        $serv2->set([
            'open_eof_split' => true,
            'package_eof' => "\n",
        ]);


        $serv2->on("receive", function(\swoole_server $server, $fd, $fromReactorId, $recv) use($port2) {
            assert(intval($recv) === $port2);
            $r = $server->send($fd, opcode_encode("return", $port2));
            assert($r !== false);
        });

    }

    public function start($lifetime = 1000)
    {
        $this->lifetime = $lifetime;

        $this->swooleServer->on('start', [$this, 'onStart']);
        $this->swooleServer->on('shutdown', [$this, 'onShutdown']);

        $this->swooleServer->on('workerStart', [$this, 'onWorkerStart']);
        $this->swooleServer->on('workerStop', [$this, 'onWorkerStop']);
        $this->swooleServer->on('workerError', [$this, 'onWorkerError']);

        $this->swooleServer->on('connect', [$this, 'onConnect']);

        $this->swooleServer->on('close', [$this, 'onClose']);

        $this->swooleServer->start();
    }

    public function onConnect() { }
    public function onClose() { }
    public function onStart(\swoole_server $swooleServer) { }
    public function onShutdown(\swoole_server $swooleServer) { }
    public function onWorkerStart(\swoole_server $swooleServer, $workerId)
    {
        if ($workerId === 0) {
            swoole_timer_after($this->lifetime, function() {
                $this->swooleServer->shutdown();
                kill_self_and_descendant(getmypid());
                /*
                \swoole_process::signal(SIGTERM, swoole_function() {
                    $this->swooleServer->shutdown();
                });
                \swoole_process::kill(0, SIGTERM);
                */
            });
        }
    }
    public function onWorkerStop(\swoole_server $swooleServer, $workerId) { }
    public function onWorkerError(\swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo) { }
}
