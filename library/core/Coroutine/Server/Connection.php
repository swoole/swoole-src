<?php

namespace Swoole\Coroutine\Server;

use Swoole\Coroutine\Socket;

class Connection
{
    public $socket;

    public function __construct(Socket $conn)
    {
        $this->socket = $conn;
    }

    public function recv($timeout = 0)
    {
        return $this->socket->recvPacket($timeout);
    }

    public function send($data)
    {
        return $this->socket->sendAll($data);
    }

    public function close()
    {
        return $this->socket->close();
    }
}
