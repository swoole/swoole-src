<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

// (new OpcodeServer("127.0.0.1", 9999))->start(PHP_INT_MAX);

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;
$port1 = isset($argv[3]) ? $argv[3] : null;
$port2 = isset($argv[4]) ? $argv[4] : null;

(new OpcodeServer($host, $port, $port1, $port2))->start();

class OpcodeServer
{
    /**
     * @var \swoole_server
     */
    public $swooleServer;

    public function __construct($host, $port, $port1 = null, $port2 = null)
    {
	    $this->swooleServer = new \swoole_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            'dispatch_mode' => 3,
            'worker_num' => 2,
            'task_worker_num' => 2,

            'open_length_check' => 1,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 0,
        	"heartbeat_idle_time"=> 20
        ]);

        if ($port1) {
            $serv1 = $this->swooleServer->addListener(TCP_SERVER_HOST, $port1, SWOOLE_SOCK_TCP);
            assert($serv1 !== false);
        }
        if ($port2) {
            $serv2 = $this->swooleServer->addListener(TCP_SERVER_HOST, $port2, SWOOLE_SOCK_TCP);
            assert($serv2 !== false);
        }
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
        $this->swooleServer->on('receive', [$this, 'onReceive']);

        $this->swooleServer->on('close', [$this, 'onClose']);

        $this->swooleServer->on('task', [$this, 'onTask']);
        $this->swooleServer->on('finish', [$this, 'onFinish']);
        $this->swooleServer->on('pipeMessage', [$this, 'onPipeMessage']);
        $this->swooleServer->on('packet', [$this, 'onPacket']);

        /*
        $proc = new \swoole_process(swoole_function(\swoole_process $proc) use($i) {
            var_dump($this->swooleServer->id);
            sleep(10000);
            $r  = $this->swooleServer->addProcess($proc);
            var_dump($r);
            $proc->freeQueue();
        });
        $proc->useQueue();
        // $proc->start();

        $proc1 = new \swoole_process(swoole_function(\swoole_process $proc) use($i) {
            var_dump($this->swooleServer->id);
            sleep(1000);
        });

        $proc2 = new \swoole_process(swoole_function(\swoole_process $proc) {
            var_dump($this->swooleServer->id);
            sleep(1000);
        });


        $r = $this->swooleServer->addProcess($proc);
        $r = $this->swooleServer->addProcess($proc1);
        $r = $this->swooleServer->addProcess($proc2);
        var_dump($this->swooleServer->id);
        */

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
    public function onReceive(\swoole_server $swooleServer, $fd, $fromReactorId, $recv)
    {
        list($op, $args) = opcode_decode($recv);

        switch($op) {
            case "sendMessage":
                list($msg, $toWorkerId) = $args;
                $r = $swooleServer->sendMessage(json_encode([
                    "fd" => $fd,
                    "msg" => $msg,
                ]), $toWorkerId);
                assert($r);
                return;

            case "sendfile":
                $len = filesize(__FILE__);
                $r = $swooleServer->send($fd, pack("N", $len + 4));
                assert($r !== false);
                $r =$swooleServer->sendfile($fd, __FILE__);
                assert($r !== false);
                return;

            default:
                if (method_exists($swooleServer, $op)) {
                    $r = call_user_func_array([$swooleServer, $op], $args);
                    if (is_resource($r)) {
                        $r = true;
                    }
                    $r = $swooleServer->send($fd, opcode_encode("return", $r));
                    assert($r !== false);
                    return;
                } else {

                }
        }
    }

    public function onTask(\swoole_server $swooleServer, $taskId, $fromWorkerId, $recv)
    {
        $recv = json_decode($recv);
        assert(json_last_error() === JSON_ERROR_NONE);
        return json_encode($recv);
    }

    public function onFinish(\swoole_server $swooleServer, $taskId, $recv)
    {
        $recv = json_decode($recv);
        assert(json_last_error() === JSON_ERROR_NONE);
        assert(isset($recv["fd"]) && isset($recv["data"]));
        $this->swooleServer->send($recv["fd"], opcode_encode("return", $recv["data"]));
    }

    public function onPipeMessage(\swoole_server $swooleServer, $fromWorkerId, $recv)
    {
        $recv = json_decode($recv, true);
        assert(json_last_error() === JSON_ERROR_NONE);
        assert(isset($recv["fd"]) && isset($recv["msg"]));
        $this->swooleServer->send($recv["fd"], opcode_encode("return", $recv["msg"]));
    }

    public function onPacket(\swoole_server $swooleServer, $data, array $clientInfo)
    {

    }
}
