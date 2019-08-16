<?php

namespace Swoole\Coroutine;

use Swoole\Coroutine;
use Swoole\Coroutine\Server\Connection;
use Swoole\Exception;

class Server
{
    public $host;
    public $port;
    public $type;
    public $fd;
    public $errCode;

    protected $running;

    protected $fn = null;

    /**
     * @var Socket
     */
    protected $socket;

    /**
     * @var array
     */
    public $setting;

    /**
     * Server constructor.
     * @param string $host
     * @param int $port
     * @param bool $ssl
     * @param bool $reuse_port
     * @throws Exception
     */
    public function __construct(string $host, int $port = 0, bool $ssl = false, $reuse_port = false)
    {
        $_host = swoole_string($host);
        if ($_host->contains('::')) {
            $this->type = AF_INET6;
        } else if ($_host->startsWith('unix:/')) {
            $host = $_host->substr(5)->__toString();
            $this->type = AF_UNIX;
        } else {
            $this->type = AF_INET;
        }
        $this->host = $host;

        $sock = new Socket($this->type, SOCK_STREAM, 0);
        if ($reuse_port and defined('SO_REUSEPORT')) {
            $sock->setOption(SOL_SOCKET, SO_REUSEPORT, true);
        }
        if (!$sock->bind($this->host, $port)) {
            throw new Exception("bind({$this->host}:$port) failed", $sock->errCode);
        }
        if (!$sock->listen()) {
            throw new Exception("listen() failed", $sock->errCode);
        }
        $this->port = $sock->getsockname()['port'] ?? 0;
        $this->fd = $sock->fd;
        $this->socket = $sock;
        $this->setting['open_ssl'] = $ssl;
    }

    public function set(array $setting)
    {
        $this->setting = array_merge($this->setting, $setting);
    }

    public function handle(callable $fn)
    {
        $this->fn = $fn;
    }

    public function shutdown()
    {
        $this->running = false;
        return $this->socket->cancel();
    }

    public function start()
    {
        $this->running = true;
        if ($this->fn == null) {
            $this->errCode = SOCKET_EINVAL;
            return false;
        }
        $socket = $this->socket;
        if (!$socket->setProtocol($this->setting)) {
            $this->errCode = SOCKET_EINVAL;
            return false;
        }

        while ($this->running) {
            /**
             * @var $conn Socket
             */
            $conn = $socket->accept();
            if ($conn) {
                $conn->setProtocol($this->setting);
                if (Coroutine::create($this->fn, new Connection($conn)) < 0) {
                    goto _wait;
                }
            } else {
                if ($socket->errCode == SOCKET_EMFILE or $socket->errCode == SOCKET_ENFILE) {
                    _wait:
                    Coroutine::sleep(1);
                    continue;
                } elseif ($socket->errCode == SOCKET_ETIMEDOUT) {
                    continue;
                } elseif ($socket->errCode == SOCKET_ECANCELED) {
                    break;
                } else {
                    trigger_error("accept failed, Error: {$socket->errMsg}[{$socket->errCode}]", E_USER_WARNING);
                    break;
                }
            }
        }
    }
}
