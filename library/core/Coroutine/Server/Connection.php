<?php

namespace Swoole\Coroutine\Server;

use Swoole\Coroutine\Socket;

class Connection
{
    public $socket;

    function __construct(Socket $conn)
    {
        $this->socket = $conn;
    }

    function recv($timeout = 0)
    {
        return $this->socket->recvPacket($timeout);
    }

    function send($data)
    {
        return $this->socket->sendAll($data);
    }

    function close()
    {
        return $this->socket->close();
    }
}