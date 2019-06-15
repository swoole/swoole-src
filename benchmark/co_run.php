<?php

namespace Swoole;

//关闭错误输出
//error_reporting(0);

class CoBenchMarkTest
{
    protected $nConcurrency = 100;
    protected $nRequest = 10000; // total
    protected $nShow;

    protected $scheme;
    protected $host;
    protected $port = 9501;

    protected $nRecvBytes = 0;
    protected $nSendBytes = 0;

    protected $requestCount = 0; // success
    protected $connectCount = 0;

    protected $connectTime = 0;

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;

    protected $sentData;
    protected $sentLen = 1024;

    public function __construct($opt)
    {
        $this->parseOpts();
        $this->setSentData(str_repeat('A', $this->sentLen));
        if (!isset($this->scheme) or !method_exists($this, $this->scheme)) {
            throw new \RuntimeException("Not support pressure measurement objects [{$this->scheme}].");
        }
        $this->testMethod = $this->scheme;
    }

    protected function parseOpts()
    {
        $shortOpts = "c:n:l:s:h";
        $opts = getopt($shortOpts);

        if (isset($opts['h'])) {
            $this->showHelp();
        }

        if (isset($opts['c']) and intval($opts['c']) > 0) {
            $this->nConcurrency = intval($opts['c']);
        }
        if (isset($opts['n']) and intval($opts['n']) > 0) {
            $this->nRequest = intval($opts['n']);
        }
        $this->nShow = $this->nRequest / 10;
        
        if (isset($opts['l']) and intval($opts['l']) > 0) {
            $this->sentLen = intval($opts['l']);
        }

        if (!isset($opts['s'])) {
            exit("Require -s [server_url]. E.g: -s tcp://127.0.0.1:9501" . PHP_EOL);
        }

        $serv = parse_url($opts['s']);
        $this->scheme = $serv['scheme'];
        if (filter_var($serv['host'], FILTER_VALIDATE_IP) === false) {
            exit("Invalid ip address" . PHP_EOL);
        }
        $this->host = $serv['host'];
        if (isset($serv['port']) and intval($serv['port']) > 0) {
            $this->port = $serv['port'];
        }
    }

    public function showHelp()
    {
        exit(<<<HELP
Usage: php co_run.php [OPTIONS]

A bench script

Options:
  -c      Number of coroutines      E.g: -c 100
  -n      Number of requests        E.g: -n 10000
  -l      The length of the data sent per request       E.g: -l 1024
  -s      URL       E.g: -s tcp://127.0.0.1:9501
\n
HELP
        );
    }

    public function setSentData($data)
    {
        $this->sentData = $data;
        $this->sentLen = strlen($data);
    }

    protected function finish()
    {
        $costTime = $this->format(microtime(true) - $this->startTime);
        $nRequest = number_format($this->nRequest);
        $requestErrorCount = number_format($this->nRequest - $this->requestCount);
        $connectErrorCount = number_format($this->nConcurrency - $this->connectCount);
        $nSendBytes = number_format($this->nSendBytes);
        $nRecvBytes = number_format($this->nRecvBytes);
        $requestPerSec = $this->requestCount / $costTime;
        $connectTime = $this->format($this->connectTime);

        echo <<<EOF
Concurrency Level:      {$this->nConcurrency}
Time taken for tests:   {$costTime} seconds
Complete requests:      {$nRequest}
Failed requests:        {$requestErrorCount}
Connect failed:         {$connectErrorCount}
Total send:             {$nSendBytes} bytes
Total reveive:          {$nRecvBytes} bytes
Requests per second:    {$requestPerSec}
Connection time:        {$connectTime} seconds
\n
EOF;
    }

    public function format($time)
    {
        return round($time, 4);
    }

    protected function websocket()
    {
        $cli = new Coroutine\http\client($this->host, $this->port);
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

    protected function tcp()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(function () use ($cli) {
            $cli->close();
        });

        if ($cli->connect($this->host, $this->port) === false) {
            echo swoole_strerror($cli->errCode) . PHP_EOL;
            return;
        }
        $this->connectCount++;

        while ($n--) {
            //requset
            if ($cli->send($this->sentData) === false) {
                echo swoole_strerror($cli->errCode) . PHP_EOL;
                continue;
            }
            $this->nSendBytes += $this->sentLen;
            $this->requestCount++;
            if ($this->requestCount % $this->nShow === 0) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            //response
            $recvData = $cli->recv();
            if ($recvData === false) {
                echo swoole_strerror($cli->errCode) . PHP_EOL;
            } else {
                $this->nRecvBytes += strlen($recvData);
            }
        }
    }

    protected function eof()
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

    protected function length()
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

    public function run()
    {
        $this->startTime = microtime(true);
        for ($i = 0; $i < $this->nConcurrency; $i++) {
            go(function () {
                call_user_func([$this, $this->testMethod]);
            });
        }
        $this->beginSendTime = microtime(true);
        $this->connectTime = $this->beginSendTime - $this->startTime;
        Event::wait();
        echo "\n\n";
        $this->finish();
    }
}

$swooleVersion = SWOOLE_VERSION;

echo <<<EOF
============================================================
Swoole Version          {$swooleVersion}
============================================================
\n
EOF;

$bench = new CoBenchMarkTest($opt);
$bench->run();
