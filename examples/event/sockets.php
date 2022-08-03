<?php
/**
 * require ./configure --enable-sockets
 */

use Swoole\Event;

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die("Unable to create socket\n");

socket_set_nonblock($socket) or die("Unable to set nonblock on socket\n");

function socket_onRead($socket)
{
    static $i = 0;

    echo socket_read($socket, 8192) . "\n";
    $i++;
    if ($i > 10) {
        echo "finish\n";
        Event::del($socket);
        socket_close($socket);
    } else {
        sleep(1);
        Event::set($socket, null, 'socket_onWrite', SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE);
    }
}

function socket_onWrite($socket)
{
    socket_write($socket, "hi swoole");
    Event::set($socket, null, null, SWOOLE_EVENT_READ);
}

function socket_onConnect($socket)
{
    $err = socket_get_option($socket, SOL_SOCKET, SO_ERROR);
    if ($err == 0) {
        echo "connect server success\n";
        Event::set($socket, null, 'socket_onWrite', SWOOLE_EVENT_READ);
        socket_write($socket, "first package\n");
    } else {
        echo "connect server failed\n";
        Event::del($socket);
        socket_close($socket);
    }
}

Event::add($socket, 'socket_onRead', 'socket_onConnect', SWOOLE_EVENT_WRITE);
socket_connect($socket, '127.0.0.1', 9501);
Event::wait();
