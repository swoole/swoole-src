<?php

use Swoole\Coroutine;

//关闭错误输出
//error_reporting(0);
$shortopts = "c:";
$shortopts .= "n:";
$shortopts .= "s:";
$shortopts .= "f:";
$shortopts .= "p::";
$shortopts .= "l:";
$shortopts .= "h";

$opt = getopt($shortopts);

if (isset($opt['h'])) {
    exit(<<<HELP
Usage: php co_run.php [OPTIONS]

A bench script

Options:
  -c      Number of coroutines
  -n      Number of requests
  -s      URL
  -f      Supported pressure measurement objects
  -l      The length of the data sent per request
\n
HELP
    );
}

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
    exit("require -f [test_function]. ep: -f websocket|http|tcp|udp|length\n");
}

class CoBenchMarkTest
{
    protected $nConcurrency;
    protected $nRequest;
    protected $host;
    protected $port;

    protected $nRecvBytes = 0;
    protected $nSendBytes = 0;

    protected $requestCount = 0;
    protected $connectErrorCount = 0;

    protected $connectTime = 0;

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;

    protected $sentData = "hello world\n";

    function __construct($opt)
    {
        $this->nConcurrency = $opt['c'];
        $this->nRequest = $opt['n'];
        $serv = parse_url($opt['s']);
        $this->host = $serv['host'];
        $this->port = $serv['port'];
        $this->testMethod = $opt['f'];

        //data length
        if (isset($opt['l']) and intval($opt['l']) > 0) {
            $this->setSentData(str_repeat('A', intval($opt['l'])));
        }

        if (!method_exists($this, $this->testMethod)) {
            throw new RuntimeException("method [{$this->testMethod}] is non-existent.");
        }
    }

    function setSentData($data)
    {
        $this->sentData = $data;
    }

    protected function finish()
    {
        echo "============================================================\n";
        echo "              Swoole Version " . SWOOLE_VERSION . "\n";
        echo "============================================================\n";
        echo "{$this->requestCount}\tbenchmark tests is finished.\n";
        echo "SendBytes:\t" . number_format($this->nSendBytes) . "\n";
        echo "RecvBytes:\t" . number_format($this->nRecvBytes) . "\n";
        echo "concurrency:\t" . $this->nConcurrency, "\n";
        echo "connect failed:\t" . $this->connectErrorCount, "\n";
        echo "request num:\t" . $this->nRequest, "\n";
        $costTime = $this->format(microtime(true) - $this->startTime);
        echo "total time:\t" . ($costTime) . "\n";
        if ($this->requestCount > 0) {
            echo "request per second:\t" . intval($this->requestCount / $costTime), "\n";
        } else {
            echo "request per second:\t0\n";
        }
        echo "connection time:\t" . $this->format($this->connectTime) . "\n";
    }

    function format($time)
    {
        return round($time, 4);
    }

    function websocket()
    {
        $cli = new Swoole\Coroutine\http\client($this->host, $this->port);
        $cli->set(array('websocket_mask' => true));
        $cli->upgrade('/');
        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            //requset
            $data = $this->sentData;
            $cli->push($data);
            $this->nSendBytes += strlen($data);
            $this->requestCount++;
            //response
            $frame = $cli->recv();
            $this->nRecvBytes += strlen($frame->data);
        }
        $cli->close();
    }

    function eof()
    {
        $eof = "\r\n\r\n";
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $cli->set(array('open_eof_check' => true, "package_eof" => $eof));
        $cli->connect($this->host, $this->port);
        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            //requset
            $data = $this->sentData . $eof;
            $cli->send($data);
            $this->nSendBytes += strlen($data);
            $this->requestCount++;
            //response
            $rdata = $cli->recv();
            $this->nRecvBytes += strlen($rdata);
        }
        $cli->close();
    }

    function length()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $cli->set(array(
            'open_length_check' => true,
            "package_length_type" => 'N',
            'package_body_offset' => 4,
        ));
        $cli->connect($this->host, $this->port);
        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            //requset
            $data = pack('N', strlen($this->sentData)) . $this->sentData;
            $cli->send($data);
            $this->nSendBytes += strlen($data);
            $this->requestCount++;
            //response
            $rdata = $cli->recv();
            $this->nRecvBytes += strlen($rdata);
        }
        $cli->close();
    }

    function run()
    {
        $this->startTime = microtime(true);
        for ($i = 0; $i < $this->nConcurrency; $i++) {
            go(function () {
                call_user_func([$this, $this->testMethod]);
            });
        }
        $this->beginSendTime = microtime(true);
        $this->connectTime = $this->beginSendTime - $this->startTime;
        swoole_event::wait();
        $this->finish();
    }
}

$bench = new CoBenchMarkTest($opt);
$bench->setSentData(str_repeat('A', 1024));
$bench->run();
