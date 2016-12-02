<?php
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
    exit("require -f [test_function]. ep: -f websocket|http|tcp|udp\n");
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
    protected $connectErrorCount = 0;

    protected $connectTime = 0;

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;

    static $sentData = "hello world\n";

    function __construct($opt)
    {
        $this->nConcurrency = $opt['c'];
        $this->nRequest = $opt['n'];
        $serv = parse_url($opt['s']);
        $this->host = $serv['host'];
        $this->port = $serv['port'];
        $this->testMethod = $opt['f'];
        if (!method_exists($this, $this->testMethod))
        {
            throw new RuntimeException("method [{$this->testMethod}] is not exists.");
        }
    }

    protected function finish()
    {
        foreach($this->clients as $k => $cli)
        {
            /**
             * @var $cli swoole\client
             */
            if ($cli->isConnected())
            {
                $cli->close();
            }
            unset($this->clients[$k]);
        }
        echo "============================================================\n";
        echo "              Swoole Version ".SWOOLE_VERSION."\n";
        echo "============================================================\n";
        echo "{$this->requestCount}\tbenchmark tests is finished.\n";
        echo "SendBytes:\t".number_format($this->nSendBytes)."\n";
        echo "nReceBytes:\t".number_format($this->nRecvBytes)."\n";
        echo "concurrency:\t".$this->nConcurrency,"\n";
        echo "connect failed:\t" . $this->connectErrorCount, "\n";
        echo "request num:\t" . $this->nRequest, "\n";
        $costTime = $this->format(microtime(true) - $this->startTime);
        echo "total time:\t" . ($costTime) . "\n";
        if ($this->requestCount > 0)
        {
            echo "request per second:\t" . intval($this->requestCount / $costTime), "\n";
        }
        else
        {
            echo "request per second:\t0\n";
        }
        echo "connection time:\t" . $this->format($this->connectTime) . "\n";
    }

    function format($time)
    {
        return round($time, 4);
    }

    function onReceive($cli, $data)
    {
        $this->nRecvBytes += strlen($data);
        /**
         * 请求已经发完了，关闭连接，等待所有连接结束
         */
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
        $data = self::$sentData;
        $cli->send($data);
        $this->nSendBytes += strlen($data);
        $this->requestCount++;
    }

    function push($cli)
    {
        $data = self::$sentData;
        $cli->push($data);
        $this->nSendBytes += strlen($data);
        $this->requestCount++;
    }

    function onClose($cli)
    {
        //echo "close\n";
    }

    function onError($cli)
    {
        $this->connectErrorCount ++;
        if ($this->connectErrorCount >= $this->nConcurrency)
        {
            $this->finish();
        }
    }

    function onConnect($cli)
    {
        $this->send($cli);
    }

    function websocket()
    {
        $cli = new swoole\http\client($this->host, $this->port);
        $cli->set(array('websocket_mask' => true));
        $cli->on('Message', function($cli, $frame) {
            $this->nRecvBytes += strlen($frame->data);
            /**
             * 请求已经发完了，关闭连接，等待所有连接结束
             */
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
                $this->push($cli);
            }
        });
        $cli->upgrade('/', function ($cli) {
            $this->push($cli);
        });
        return $cli;
    }

    function long_tcp()
    {
        $cli = new swoole\client(SWOOLE_TCP | SWOOLE_ASYNC);
        $cli->on('receive', [$this, 'onReceive']);
        $cli->on('close', [$this, 'onClose']);
        $cli->on('connect', [$this, 'onConnect']);
        $cli->on('error', [$this, 'onError']);
        $cli->connect($this->host, $this->port);
        return $cli;
    }

    function eof()
    {
        $eof = "\r\n\r\n";
        $cli = new swoole\client(SWOOLE_TCP | SWOOLE_ASYNC);
        $cli->set(array('open_eof_check' => true, "package_eof" => $eof));
        $cli->on('receive', [$this, 'onReceive']);
        $cli->on('close', [$this, 'onClose']);
        $cli->on('connect', [$this, 'onConnect']);
        $cli->on('error', [$this, 'onError']);
        $cli->connect($this->host, $this->port);
        self::$sentData .= $eof;
        return $cli;
    }

    function length()
    {
        $cli = new swoole\client(SWOOLE_TCP | SWOOLE_ASYNC);
        $cli->set(array(
            'open_length_check' => true,
            "package_length_type" => 'N',
            'package_body_offset' => 4,
        ));
        $cli->on('receive', [$this, 'onReceive']);
        $cli->on('close', [$this, 'onClose']);
        $cli->on('connect', [$this, 'onConnect']);
        $cli->on('error', [$this, 'onError']);
        $cli->connect($this->host, $this->port);
        self::$sentData = pack('N', strlen(self::$sentData)) . self::$sentData;
        return $cli;
    }

    function udp()
    {
        $cli = new swoole\client(SWOOLE_UDP | SWOOLE_ASYNC);
        $cli->on('receive', [$this, 'onReceive']);
        $cli->on('close', [$this, 'onClose']);
        $cli->on('connect', [$this, 'onConnect']);
        $cli->on('error', [$this, 'onError']);
        $cli->connect($this->host, $this->port);
        return $cli;
    }

    function run()
    {
        $this->startTime = microtime(true);
        for ($i = 0; $i < $this->nConcurrency; $i++)
        {
            $cli = call_user_func([$this, $this->testMethod]);
            $this->clients[$cli->sock] = $cli;
        }
        $this->beginSendTime = microtime(true);
        $this->connectTime = $this->beginSendTime - $this->startTime;
    }
}

$bench = new BenchMark($opt);
$bench->run();
