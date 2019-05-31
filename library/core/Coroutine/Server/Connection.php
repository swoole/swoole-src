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

    function recv($length = 8192)
    {
        return $this->socket->recv($length);
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