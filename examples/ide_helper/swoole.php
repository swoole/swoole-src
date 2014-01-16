<?php
define('SWOOLE_VERSION', '1.6.9');
define('SWOOLE_SOCK_TCP', 1);
define('SWOOLE_SOCK_UDP', 2);
define('SWOOLE_SOCK_ASYNC', 2);
define('SWOOLE_SOCK_SYNC', 1);

class swoole_server
{
    function __construct($host, $port, $mode = 3, $tcp_or_udp = 1){}
    function on($event_name, $callback_function){}
    function set(array $config){}
    function start(){}
    function send($fd, $response, $from_id = 0){}
    function close($fd, $from_id = 0){}
}

class swoole_client
{
    public $sock;
    function on($event_name, $callback_function){}
    function send($data){}
    function close(){}
    function recv($length, $waitall = 0){}
    function connect($ip, $port, $timeout_float = 0.5, $udp_connect_tcp_nonblock = 0){}
}