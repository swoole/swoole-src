<?php

namespace SwooleBench;

use Swoole\Coroutine;
use Swoole\ExitException;
use Symfony\Component\Console\Application;
use Symfony;

class Base
{
    protected const SENT_LEN = 1024;
    protected const TIMEOUT = 3; // seconds
    protected const PATH = '/';
    protected const QUERY = '';

    protected $nConcurrency = 100;
    protected $nRequest = 10000; // total
    protected $nShow;
    protected $clientSocketType = SWOOLE_SOCK_TCP;

    protected $scheme;
    protected $host;
    protected $port;
    protected $path = '/';
    protected $query;

    protected $nRecvBytes = 0;
    protected $nSendBytes = 0;

    protected $requestCount = 0; // success
    protected $connectCount = 0;
    protected $connectErrorCount = 0;
    protected $contentErrorCount = 0;
    protected $connectTime = 0;

    protected $keepAlive; // default disable
    protected $timeout; // seconds

    protected $startTime;
    protected $beginSendTime;
    protected $testMethod;
    protected $sentLength = self::SENT_LEN;
    protected $enableEofProtocol = false;
    protected $packetEofString = "\r\n\r\n";
    protected $enableLengthProtocol = false;
    public $verbose = false;
    public $writeOnly;
    protected $packetIndex = 0;

    /**
     * Base constructor.
     * @param $c
     * @param $n
     * @param $s
     * @param $f
     * @throws ExitException
     */
    function __construct($c, $n, $s, $f)
    {
        list($this->host, $this->port) = explode(':', $s);
        if (!filter_var($this->host, FILTER_VALIDATE_IP)) {
            throw new ExitException("Invalid ip address: {$this->host}" . PHP_EOL);
        }
        if ($this->port > 65535 or $this->port < 1024) {
            throw new ExitException("Invalid port [1024~65535]" . PHP_EOL);
        }

        $this->nConcurrency = $c;
        $this->nRequest = $n;

        if (!isset($f) or !method_exists($this, $f)) {
            throw new ExitException("Not support pressure measurement objects [{$f}]." . PHP_EOL);
        }
        $this->testMethod = $f;
        $this->nShow = $this->nRequest / 10;
    }

    public function setDataLength($l)
    {
        $this->sentLength = $l;
    }

    public function setVerbose()
    {
        $this->verbose = true;
    }

    protected function finish()
    {
        $costTime = $this->format(microtime(true) - $this->startTime);
        $nRequest = number_format($this->nRequest);
        $requestErrorCount = number_format($this->nRequest - $this->requestCount);
        $connectErrorCount = number_format($this->connectErrorCount);
        $nSendBytes = number_format($this->nSendBytes);
        $nRecvBytes = number_format($this->nRecvBytes);
        $requestPerSec = round($this->requestCount / $costTime, 2);
        $connectTime = $this->format($this->connectTime);

        $output = '';
        $output .= "Concurrency Level:      {$this->nConcurrency}";
        $output .= "\nTime taken for tests:   {$costTime} seconds";
        $output .= "\nComplete requests:      {$nRequest}";
        $output .= "\nFailed requests:        " . $this->prettifyNumber($requestErrorCount);
        $output .= "\nConnect failed:         {$connectErrorCount}";
        $output .= "\nTotal send:             {$nSendBytes} bytes";
        $output .= "\nTotal reveive:          {$nRecvBytes} bytes";
        $output .= "\nRequests per second:    {$requestPerSec}";
        $output .= "\nConnection time:        {$connectTime} seconds";
        $output .= "\nContent Error:          " . $this->prettifyNumber($this->contentErrorCount);
        $output .= "\n";
        echo $output;
    }

    protected function prettifyNumber($n)
    {
        return ($n == 0 ? color(
            '0',
            SWOOLE_COLOR_GREEN
        ) : color(
            $n,
            SWOOLE_COLOR_RED
        ));
    }

    public function format($time)
    {
        return round($time, 4);
    }

    protected function verifyResponse($req, $resp)
    {
        if ($this->enableLengthProtocol) {
            if ($resp !== $req) {
                $this->contentErrorCount++;
            }
        } else {
            if ($resp !== get_response($req)) {
                $this->contentErrorCount++;
            }
        }
        $this->nRecvBytes += strlen($resp);
    }

    function ws()
    {
        $this->websocket();
    }

    protected function websocket()
    {
        $wsCli = new Coroutine\Http\Client($this->host, $this->port);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(function () use ($wsCli) {
            $wsCli->close();
        });

        $setting = [
            'timeout' => $this->timeout,
            'websocket_mask' => true,
        ];
        $wsCli->set($setting);
        if (!$wsCli->upgrade('/')) {
            if ($wsCli->errCode === 111) {
                throw new ExitException(swoole_strerror($wsCli->errCode));
            } else if ($wsCli->errCode === 110) {
                throw new ExitException(swoole_strerror($wsCli->errCode));
            } else {
                throw new ExitException("Handshake failed");
            }
        }

        while ($n--) {
            $sentData = $this->getRandomData($this->sentLength, false);
            if (!$wsCli->push($sentData)) {
                if ($wsCli->errCode === 8502) {
                    throw new ExitException("Error OPCODE");
                } elseif ($wsCli->errCode === 8503) {
                    throw new ExitException("Not connected to the server or the connection has been closed");
                } else {
                    throw new ExitException("Handshake failed");
                }
            }
            $this->nSendBytes += strlen($sentData);
            $this->requestCount++;
            if (($this->requestCount % $this->nShow === 0) and $this->verbose) {
                $this->trace("Completed {$this->requestCount} requests");
            }
            //response
            $frame = $wsCli->recv();
            if (!$frame or !$frame->data) {
                break;
            } else {
                $this->verifyResponse($sentData, $frame->data);
            }
        }
    }

    function dtls()
    {
        $this->clientSocketType = SWOOLE_UDP | SWOOLE_SSL;
        $this->execute();
    }

    protected function trace($log)
    {
        if ($this->verbose) {
            echo $log . "\n";
        }
    }

    function udp()
    {
        $this->clientSocketType = SWOOLE_SOCK_UDP;
        $this->execute();
    }

    /**
     * @throws ExitException
     */
    function tcp()
    {
        $this->clientSocketType = SWOOLE_SOCK_TCP;
        $this->execute();
    }

    protected function execute()
    {
        $cli = new Coroutine\Client($this->clientSocketType);
        $n = $this->nRequest / $this->nConcurrency;
        Coroutine::defer(
            function () use ($cli) {
                $cli->close();
            }
        );

        if (!$cli->connect($this->host, $this->port)) { // connection failed
            if ($cli->errCode === SOCKET_ECONNREFUSED) { // connection refuse
                throw new ExitException(swoole_strerror($cli->errCode));
            }
            if ($cli->errCode === SOCKET_ETIMEDOUT) { // connection timeout
                $this->connectErrorCount++;
                if ($this->verbose) {
                    echo swoole_strerror($cli->errCode) . PHP_EOL;
                }
                return;
            }
        }

        $this->trace("connect success");

        if ($this->enableEofProtocol) {
            $cli->set(array('open_eof_check' => true, "package_eof" => $this->packetEofString));
        } elseif ($this->enableLengthProtocol) {
            $cli->set(
                array(
                    'open_length_check' => true,
                    "package_length_type" => 'N',
                    'package_body_offset' => 4,
                )
            );
        }

        while ($n--) {
            //requset
            $sentData = $this->getRandomData($this->sentLength);
            $this->trace("send data, length=".strlen($sentData));
            if (!$cli->send($sentData)) {
                if ($this->verbose) {
                    echo swoole_strerror($cli->errCode) . PHP_EOL;
                }
                continue;
            }
            $this->nSendBytes += strlen($sentData);
            $this->requestCount++;
            if (($this->requestCount % $this->nShow === 0) and $this->verbose) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            //response
            $recvData = $cli->recv();
            if ($recvData === false and $this->verbose) {
                echo swoole_strerror($cli->errCode) . PHP_EOL;
            } else {
                $this->verifyResponse($sentData, $recvData);
            }
        }
    }

    /**
     * @throws ExitException
     */
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
            'content-type' => 'application/binary-data',
        ];
        $httpCli->setHeaders($headers);

        $setting = [
            'timeout' => $this->timeout,
            'keep_alive' => $this->keepAlive,
        ];

        $httpCli->set($setting);

        $query = empty($this->query) ? '' : "?$this->query";

        while ($n--) {
            $sentData = $this->getRandomData($this->sentLength);
            $httpCli->setData($sentData);
            $httpCli->execute("{$this->path}{$query}");

            if (!$this->checkStatusCode($httpCli)) {
                continue;
            }
            $this->nSendBytes += strlen($sentData);
            $this->requestCount++;
            if ($this->requestCount % $this->nShow === 0 and $this->verbose) {
                echo "Completed {$this->requestCount} requests" . PHP_EOL;
            }
            $recvData = $httpCli->body;
            $this->verifyResponse($sentData, $recvData);
        }
    }

    /**
     * @param Coroutine\Http\Client $httpCli
     * @return bool
     * @throws ExitException
     */
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
        $this->enableEofProtocol = true;
        $this->execute();
    }

    protected function length()
    {
        $this->enableLengthProtocol = true;
        $this->execute();
    }

    /**
     * @param $length
     * @return string
     */
    protected function getRandomData($length)
    {
        if ($length == 0) {
            $length = self::SENT_LEN;
        }
        try {
            $randomData = random_bytes($length);
        } catch (\Exception $e) {
            return "";
        }

        if ($this->enableEofProtocol) {
            return base64_encode($randomData) . $this->packetEofString;
        } elseif ($this->enableLengthProtocol) {
            return pack('N', strlen($randomData)) . $randomData;
        } else {
            return $randomData;
        }
    }

    protected function random_data()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $cli->set(
            array(
                'open_length_check' => true,
                "package_length_type" => 'N',
                'package_body_offset' => 4,
            )
        );
        $cli->connect($this->host, $this->port);

        $max = 32 * 1024 * 1024;

        static $random_data = null;
        if (!$random_data) {
            $random_data = $this->getRandomData($max);
        }

        $cid = Coroutine::getCid();

        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            /**
             * 随机发送一个长度为 1K-1M 的包
             */
            $len = mt_rand(1024, 1024 * 1024);
            /**
             * 随机数据，从 32M 的数据段随机中取 $len 字节
             */
            $send_data = substr($random_data, rand(0, $max - $len), $len);
            /**
             * 末尾 128 字节作为盐值，计算 md5，因为计算全量数据md5 CPU消耗过大)
             */
            $salt = substr($send_data, -128, 128);
            /**
             * 包序号，用于 debug
             */
            $id = $this->packetIndex++;
            /**
             * 格式说明：
             * (length)[4Byte] + (id)[4Byte] + (md5)(32Byte) + (data)($N Byte 随机二进制字符串)
             */
            $data = pack('NN', $len + 32 + 4, $id) . md5($salt) . $send_data;

            $cli->send($data);
            $this->nSendBytes += strlen($data);
            $this->requestCount++;
            /**
             * 只发送数据
             */
            if ($this->writeOnly) {
                continue;
            }
            //response
            $rdata = $cli->recv();
            if (!$rdata) {
                echo "[Co-$cid]\tConnection Reset\n";
                $this->contentErrorCount++;
                break;
            }
            $this->nRecvBytes += strlen($rdata);

            /**
             * 解析数据
             */
            $header = unpack('Nid', substr($data, 4, 4));
            $hash = substr($data, 8, 32);
            $salt2 = substr($data, -128, 128);
            if ($hash !== md5($salt2)) {
                $this->contentErrorCount++;
                echo "[Co-$cid]\tResponse Data Error\n";
            }
        }
        $cli->close();
    }

    protected function random_data_eof()
    {
        $cli = new Coroutine\Client(SWOOLE_TCP);
        $options = array(
            'open_eof_check' => true,
            'package_eof' => "\r\n",
        );
        $cli->set(
            $options
        );
        $cli->connect($this->host, $this->port);
        $this->enableEofProtocol = true;

        $max = 32 * 1024 * 1024;
        static $random_data = null;
        if (!$random_data) {
            $random_data = $this->getRandomData($max);
        }

        $cid = Coroutine::getCid();

        $n = $this->nRequest / $this->nConcurrency;
        while ($n--) {
            //requset
            $len = mt_rand(1024, 1024 * 1024);
            $send_data = substr($random_data, rand(0, $max - $len), $len);
            /**
             * (32Byte)[hash] + (N Byte)[data] + (2 Byte)[EOF]
             */
            $data = md5(substr($send_data, -128, 128)) . $send_data . "\r\n";
            $cli->send($data);
            $this->nSendBytes += strlen($data);
            $this->requestCount++;
            if ($this->writeOnly) {
                continue;
            }
            //response
            $rdata = $cli->recv();
            $this->nRecvBytes += strlen($rdata);
            $hash = substr($data, 0, 32);
            if ($hash !== md5(substr($data, -130, 128))) {
                echo "[Co-$cid]\tResponse Data Error\n";
                $this->contentErrorCount++;
                break;
            }
        }
        $cli->close();
    }

    public function run()
    {
        $exitException = false;
        $this->startTime = microtime(true);

        $sch = new Coroutine\Scheduler;

        $sch->parallel($this->nConcurrency, function () use (&$exitException, &$exitExceptiontMsg) {
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