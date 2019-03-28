<?php
/**
 * Author: Twosee <twose@qq.com>
 * Date: 2019/3/28 10:30 AM
 */

namespace Co;

use RuntimeException;

class TestServer
{
    /** @var Socket */
    protected $server = null;
    /** @var Socket[] */
    protected $connections = [];
    /** @var callable */
    protected $dataHandler = null;

    public static function create(string $host = '127.0.0.1', int $port = 0, int $backlog = 128): self
    {
        return new self([
            'host' => $host,
            'port' => $port,
            'backlog' => $backlog
        ]);
    }

    public static function createHttpHelloWorld(...$args): self
    {
        $server = self::create(...$args);
        $server->setDataHandler(function (Socket $conn, string $data) {
            if (strpos($data, 'HTTP/1.0') !== false || stripos($data, 'Connection: closed') !== false) {
                $conn->keep_alive = false;
            }
            if (strrpos($data, "\r\n\r\n") !== false) {
                $conn->sendAll("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n");
                if (!($conn->keep_alive ?? true)) {
                    $conn->close();
                }
            }
        });
        return $server;
    }

    public function __construct(array $options)
    {
        $this->server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (!$this->server->bind($options['host'] ?? '127.0.0.1', $options['port'] ?? 9501)) {
            throw new RuntimeException("bind failed due to {$this->server->errMsg}");
        }
        if (!$this->server->listen($options['backlog'] ?? 128)) {
            throw new RuntimeException("listen failed due to {$this->server->errMsg}");
        }
    }

    public function getPort(): int
    {
        return ($this->server->getsockname() ?: [])['port'] ?? 0;
    }

    public function setDataHandler(callable $handler)
    {
        $this->dataHandler = $handler;
    }

    public function run()
    {
        go(function () {
            while ($conn = $this->server->accept(-1)) {
                $this->connections[] = $conn;
                go(function () use ($conn) {
                    while ($data = $conn->recv(8192, -1)) {
                        if ($this->dataHandler) {
                            $handler = $this->dataHandler;
                            $handler($conn, $data);
                        }
                    }
                    $conn->close();
                });
            }
            foreach ($this->connections as $conn) {
                $conn->close();
            }
            $this->server->close();
        });
    }

    public function shutdown()
    {
        $this->server->close();
    }
}
