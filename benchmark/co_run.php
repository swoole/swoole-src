<?php

namespace Swoole;

//关闭错误输出
//error_reporting(0);

class CoBenchMarkTest
{
    protected const TCP_SENT_LEN = 1024;
    protected const TIMEOUT = 3; // seconds
    protected const PATH = '/';
    protected const QUERY = '';

    protected $nConcurrency = 100;
    protected $nRequest = 10000; // total
    protected $nShow;

    protected $scheme;
    protected $host;
    protected $port;
    protected $path;
    protected $query;

    protected $nRecvBytes = 0;
    protected $nSendBytes = 0;

    protected $requestCount = 0; // success
    // protected $connectCount = 0;
    protected $connectErrorCount = 0;
    protected $connectTime = 0;

    protected $keepAlive; // default disable
    protected $timeout; // seconds

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;

    protected $sentData;
    protected $sentLen = 0;

    protected $verbose; // default disable

    public function __construct($opt)
    {
        $this->init();
    }

    protected function init()
    {
        $this->parseOpts();
        if (!isset($this->scheme) or !method_exists($this, $this->scheme)) {
            exit("Not support pressure measurement objects [{$this->scheme}]." . PHP_EOL);
        }
        $this->testMethod = $this->scheme;

        if (!isset($this->port)) {
            switch ($this->scheme) {
                case 'tcp':
                    $this->port = 9501;
                    break;
                case 'http':
                    $this->port = 80;
                    break;
                case 'https':
                    $this->port = 443;
                    break;
                case 'ws':
                    $this->port = 80;
                default:
                    break;
            }
        }
    }

    protected function parseOpts()
    {
        $shortOpts = "c:n:l:s:t:d:khv";
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
        if (!$serv) {
            exit("Invalid URL" . PHP_EOL);
        }
        $this->scheme = $serv['scheme'];
        if (!filter_var($serv['host'], FILTER_VALIDATE_IP)) {
            exit("Invalid ip address" . PHP_EOL);
        }
        $this->host = $serv['host'];
        if (isset($serv['port']) and intval($serv['port']) > 0) {
            $this->port = $serv['port'];
        }
        $this->path = $serv['path'] ?? SELF::PATH;
        $this->query = $serv['query'] ?? SELF::QUERY;

        $this->timeout = $opts['t'] ? intval($opts['t']) : SELF::TIMEOUT;
        $this->keepAlive = isset($opts['k']);
        $this->verbose = isset($opts['v']);

        if (isset($opts['d'])) {
            $this->setSentData($opts['d']);
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
                    Support: tcp、http、ws
  -t      Http request timeout detection
                    Default is 3 seconds, -1 means disable
  -k      Use HTTP KeepAlive
  -d      HTTP post data
  -h      Help list
  -v      Flag enables verbose progress and debug output
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
        $connectErrorCount = number_format($this->connectErrorCount);
        $nSendBytes = number_format($this->nSendBytes);
        $nRecvBytes = number_format($this->nRecvBytes);
        $requestPerSec = $this->requestCount / $costTime;
        $connectTime = $this->format($this->connectTime);

        echo <<<EOF
\n
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

    protected function ws()
    {
        $wsCli = new Coroutine\http\client($this->host, $this->port);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(function () use ($wsCli) {
            $wsCli->close();
        });

        $setting = [
            'timeout' => $this->timeout,
            'websocket_mask' => true,
        ];
        $wsCli->set($setting);
        if (!$wsCli->upgrade($this->path)) {
            if ($wsCli->errCode === 111) {
                throw new ExitException(swoole_strerror($wsCli->errCode));
            } else if ($wsCli->errCode === 110) {
                throw new ExitException(swoole_strerror($wsCli->errCode));
            } else {
                throw new ExitException("Handshake failed");
            }
        }

        if ($this->sentLen === 0) {
            $this->sentLen = SELF::TCP_SENT_LEN;
        }
        $this->setSentData(str_repeat('A', $this->sentLen));
       
        while ($n--) {
            //requset
            if (!$wsCli->push($this->data)) {
                if ($wsCli->errCode === 8502) {
                    throw new ExitException("Error OPCODE");
                } else if ($wsCli->errCode === 8503) {
                    throw new ExitException("Not connected to the server or the connection has been closed");
                } else {
                    throw new ExitException("Handshake failed");
                }
            }
            $this->nSendBytes += $this->sentLen;
            $this->requestCount++;
            if (($this->requestCount % $this->nShow === 0) and $this->verbose) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            //response
            $frame = $wsCli->recv();
            $this->nRecvBytes += strlen($frame->data);
        }
    }

    protected function tcp()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(function () use ($cli) {
            $cli->close();
        });

        if ($this->sentLen === 0) {
            $this->sentLen = SELF::TCP_SENT_LEN;
        }
        $this->setSentData(str_repeat('A', $this->sentLen));

        if (!$cli->connect($this->host, $this->port)) { // connection failed
            if ($cli->errCode === 111) { // connection refuse
                throw new ExitException(swoole_strerror($cli->errCode));
            }
            if ($cli->errCode === 110) { // connection timeout
                $this->connectErrorCount++;
                if ($this->verbose) {
                    echo swoole_strerror($cli->errCode) . PHP_EOL;
                }
                return;
            }
        }

        while ($n--) {
            //requset
            if (!$cli->send($this->sentData)) {
                if ($this->verbose) {
                    echo swoole_strerror($cli->errCode) . PHP_EOL;
                }
                continue;
            }
            $this->nSendBytes += $this->sentLen;
            $this->requestCount++;
            if (($this->requestCount % $this->nShow === 0) and $this->verbose) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            //response
            $recvData = $cli->recv();
            if ($recvData === false and $this->verbose) {
                echo swoole_strerror($cli->errCode) . PHP_EOL;
            } else {
                $this->nRecvBytes += strlen($recvData);
            }
        }
    }

    protected function http()
    {
        $httpCli = new Coroutine\Http\Client($this->host, $this->port);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(function () use ($httpCli) {
            $httpCli->close();
        });

        $headers = [
            'Host' => "{$this->host}:{$this->port}",
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'content-type' => 'application/x-www-form-urlencoded',
        ];
        $httpCli->setHeaders($headers);

        $setting = [
            'timeout' => $this->timeout,
            'keep_alive' => $this->keepAlive,
        ];
        $httpCli->set($setting);
        if (isset($this->sentData)) {
            $httpCli->setData($this->sentData);
        }

        $query = empty($this->query) ? '' : "?$this->query";

        while ($n--) {
            $httpCli->execute("{$this->path}{$query}");

            if (!$this->checkStatusCode($httpCli)) {
                continue;
            }

            $this->requestCount++;
            if ($this->requestCount % $this->nShow === 0 and $this->verbose) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            $recvData = $httpCli->body;
            $this->nRecvBytes += strlen($recvData);
        }
    }

    protected function checkStatusCode(Coroutine\Http\Client $httpCli): bool
    {
        if ($httpCli->statusCode === -1) { // connection failed
            if ($httpCli->errCode === 111) { // connection refused
                throw new ExitException(swoole_strerror($httpCli->errCode));
            }
            if ($httpCli->errCode === 110) { // connection timeout
                $this->connectErrorCount++;
                if ($this->verbose) {
                    echo swoole_strerror($httpCli->errCode) . PHP_EOL;
                }
                return false;
            }
        }
        
        if ($httpCli->statusCode === -2) { // request timeout
            if ($this->verbose) {
                echo swoole_strerror($httpCli->errCode) . PHP_EOL;
            }
            return false;
        }

        if ($httpCli->statusCode === 404) {
            $query = empty($this->query) ? '' : "?$this->query";
            $url = "{$this->scheme}://{$this->host}:{$this->port}{$this->path}{$query}";
            throw new ExitException("The URL [$url] is non-existent");
        }

        return true;
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
        $exitException = false;
        $exitExceptiontMsg;
        $this->startTime = microtime(true);

        $sch = new Coroutine\Scheduler;

        $sch->parallel($this->nConcurrency, function() use(&$exitException, &$exitExceptiontMsg) {
            try {
                call_user_func([$this, $this->testMethod]);
            } catch (ExitException $e) {
                $exitException = true;
                $exitExceptiontMsg = $e->getMessage();
            }
        });
        $sch->start();

        $this->beginSendTime = microtime(true);
        $this->connectTime = $this->beginSendTime - $this->startTime;
        if ($exitException) {
            exit($exitExceptiontMsg . PHP_EOL);
        }
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
