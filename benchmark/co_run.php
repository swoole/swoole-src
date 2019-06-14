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

    protected $connectTime = 0;

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;

    protected $nShow;

    protected $sentData = "hello world\n";

    function __construct($opt)
    {
        $this->nConcurrency = intval($opt['c']);
        $this->nRequest = intval($opt['n']);
        $this->nShow = $this->nRequest / 10;
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
        $costTime = $this->format(microtime(true) - $this->startTime);
        $nRequest = number_format($this->nRequest);
        $requestErrorCount = number_format($this->nRequest - $this->requestCount);
        $nSendBytes = number_format($this->nSendBytes);
        $nRecvBytes = number_format($this->nRecvBytes);
        $requestPerSec = $this->requestCount / $costTime;
        $connectTime = $this->format($this->connectTime);

        echo <<<EOF
Concurrency Level:      $this->nConcurrency 
Time taken for tests:   $costTime seconds
Complete requests:      $nRequest 
Failed requests:        $requestErrorCount
Connect failed:         $requestErrorCount
Total send:             $nSendBytes bytes
Total reveive:          $nRecvBytes bytes
Requests per second:    $requestPerSec
Connection time:        $connectTime seconds
\n
EOF;
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
        $data = $this->sentData;
        $sendLen = strlen($data);
        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            //requset
            $cli->push($data);
            $this->nSendBytes += $sendLen;
            $this->requestCount++;
            //response
            $frame = $cli->recv();
            $this->nRecvBytes += strlen($frame->data);
        }
        $cli->close();
    }

    function tcp()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $data = $this->sentData;
        $sendLen = strlen($data);
        $n = $this->nRequest / $this->nConcurrency;

        if ($cli->connect($this->host, $this->port) === false) {
            echo swoole_strerror($cli->errCode) . PHP_EOL;
            goto end;
        }

        while ($n--) {
            //requset
            if ($cli->send($data) === false) {
                echo swoole_strerror($cli->errCode);
            } else {
                $this->nSendBytes += $sendLen;
                $this->requestCount++;
                if ($this->requestCount % $this->nShow === 0) {
                    echo "Completed {$this->requestCount} requests" . PHP_EOL;
                }
                //response
                $this->nRecvBytes += strlen($cli->recv());
            }
        }

        end:
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
        echo "\n\n";
        $this->finish();
    }
}

$swooleVersion = SWOOLE_VERSION;

echo <<<EOF
============================================================
Swoole Version          $swooleVersion
============================================================
\n
EOF;

$bench = new CoBenchMarkTest($opt);
$bench->setSentData(str_repeat('A', 1024));
$bench->run();
