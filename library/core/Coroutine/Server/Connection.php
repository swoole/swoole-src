<?php

namespace Swoole\Coroutine\Server;

use Swoole\Coroutine\Socket;

class Connection
{
    protected $socket;

    public function __construct(Socket $conn)
    {
        $this->socket = $conn;
    }

    public function recv(float $timeout = 0)
    {
        return $this->socket->recvPacket($timeout);
    }

    public function send(string $data)
    {
        return $this->socket->sendAll($data);
    }

    public function close(): bool
    {
        return $this->socket->close();
    }

    public function exportSocket(): Socket
    {
        return $this->socket;
    }
}
