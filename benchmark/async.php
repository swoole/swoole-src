<?php
require dirname(__DIR__) . '/examples/websocket/WebSocketClient.php';

//关闭错误输出
//error_reporting(0);
$shortopts = "c:";
$shortopts .= "n:";
$shortopts .= "s:";
$shortopts .= "f:";
$shortopts .= "p::";

$opt = getopt($shortopts);
//并发数量
if (!isset($opt['c'])) {
    exit("require -c [process_num]. ep: -c 100\n");
}
if (!isset($opt['n'])) {
    exit("require -n [request_num]. ep: -n 10000\n");
}
if (!isset($opt['s'])) {
    exit("require -s [server_url]. ep: -s tcp://127.0.0.1:9999\n");
}
if (!isset($opt['f'])) {
    exit("require -f [test_function]. ep: -f short_tcp\n");
}

class BenchMark
{
    protected $nConcurrency;
    protected $nRequest;
    protected $host;
    protected $port;
    protected $clients = array();

    protected $nRecvBytes = 0;
    protected $nSendBytes = 0;

    protected $requestCount = 0;

    protected $connectTime = 0;

    protected $startTime;
    protected $beginSendTime;

    function __construct($opt)
    {
        $this->nConcurrency = $opt['c'];
        $this->nRequest = $opt['n'];
        $serv = parse_url($opt['s']);
        $this->host = $serv['host'];
        $this->port = $serv['port'];
    }

    protected function finish()
    {
        foreach($this->clients as $k => $cli)
        {
            $cli->close();
            unset($this->clients[$k]);
        }
        echo "{$this->requestCount}\tbenchmark tests is finished.\n";
        echo "SendBytes: {$this->nSendBytes}\n";
        echo "nReceBytes: {$this->nRecvBytes}\n";
        echo "concurrency:\t".$this->nConcurrency,"\n";
        echo "request num:\t" . $this->nRequest, "\n";
        $costTime = $this->format(microtime(true) - $this->startTime);
        echo "total time:\t" . ($costTime) . "\n";
        echo "req per second:\t" . intval($this->nRequest / $costTime), "\n";
        echo "connect: " . $this->format($this->connectTime) . "\n";
    }

    function format($time)
    {
        return round($time, 4);
    }

    function onReceive($cli, $data)
    {
        $this->nRecvBytes += strlen($data);
        if ($this->requestCount >= $this->nRequest)
        {
            $cli->close();
            unset($this->clients[$cli->sock]);
            if (count($this->clients) == 0)
            {
                $this->finish();
            }
        }
        else
        {
            $this->send($cli);
        }
    }

    function send($cli)
    {
        $data = "hello world";
        $cli->send($data);
        $this->nSendBytes += strlen($data);
        $this->requestCount++;
    }

    function onClose($cli)
    {
        //echo "close\n";
    }

    function onError($cli)
    {

    }

    function onConnect($cli)
    {
        $this->send($cli);
    }

    function run()
    {
        $this->startTime = microtime(true);
        for ($i = 0; $i < $this->nConcurrency; $i++) {
            $cli = new swoole\client(SWOOLE_TCP | SWOOLE_ASYNC);
            $cli->on('receive', [$this, 'onReceive']);
            $cli->on('close', [$this, 'onClose']);
            $cli->on('connect', [$this, 'onConnect']);
            $cli->on('error', [$this, 'onError']);
            $cli->connect($this->host, $this->port);
            $this->clients[$cli->sock] = $cli;
        }
        $this->beginSendTime = microtime(true);
        $this->connectTime = $this->beginSendTime - $this->startTime;
    }
}

$bench = new BenchMark($opt);
$bench->run();
