<?php
define('DOCUMENT_ROOT', '/var/www/html/');
/*
   argv0  server host
   argv1  server port
   argv2  server mode SWOOLE_BASE or SWOOLE_THREAD or SWOOLE_PROCESS
   argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
 */
$serv = swoole_server_create("127.0.0.1", 8848, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
swoole_server_setopt($serv, array(
            'worker_num' => 8,    //worker process num
            'backlog' => 128,   //listen backlog
            'max_request' => 20000,
            'max_conn' => 50000,
            'open_cpu_affinity' => 1,
            'open_tcp_nodelay' => 1,
            //'daemonize' => 1,
            ));

/*
   argv0  server resource
   argv1  listen host
   argv2  listen port
   argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
 */
//swoole_server_addlisten($serv, "127.0.0.1", 9500, SWOOLE_SOCK_UDP);
function my_onStart($serv)
{
    echo "Server：start\n";
}

function my_onShutdown($serv)
{
    echo "Server：onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    echo "Server：Timer Call.Interval=$interval \n";
}

function my_onClose($serv,$fd,$from_id)
{
    //$fd = $from_id = null;
    //echo "Client：Close.\n";
}

function my_onConnect($serv,$fd,$from_id)
{
    //file_put_contents('/tmp/log', getmypid() . "\t" . memory_get_usage() . "\t" . memory_get_usage(true) . "\n", FILE_APPEND);
    //echo "Client：Connect.\n";
}

function my_onWorkerStart($serv, $worker_id)
{
    file_put_contents('/tmp/log', getmypid() . "\t" . memory_get_usage() . "\t" . memory_get_usage(true) . "\n", FILE_APPEND);
    echo "WorkerStart[$worker_id]|pid=".getmypid().".\n";
}

function my_onWorkerStop($serv, $worker_id)
{
    echo "WorkerStop[$worker_id]|pid=".getmypid().".\n";
}

function my_onReceive($serv, $fd, $from_id, $data)
{
    //file_put_contents('/tmp/log', getmypid() . "\t" . memory_get_usage() . "\t" . memory_get_usage(true) . "\n", FILE_APPEND);
    //$request = http_parse($data);
    $data = "it work!";
    $data = http_package($data);
    swoole_server_send($serv, $fd, $data);
    swoole_server_close($serv, $fd, $from_id);
}

function http_package($data) {
    $httpStr = "HTTP/1.1 200 OK\r\nServer: Swoole/1.5.4\r\nConnection: Close\r\n\r\n" . $data;
    return $httpStr;
}

function http_parse($data) {

    $tmp = explode("\r\n", $data);
    list($method, $uri, $version) = explode(' ', $tmp[0]);
    return array('method' => $method, 'uri' => $uri, 'version' => $version);
}

swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onConnect', 'my_onConnect');
swoole_server_handler($serv, 'onReceive', 'my_onReceive');
swoole_server_handler($serv, 'onClose', 'my_onClose');
swoole_server_handler($serv, 'onShutdown', 'my_onShutdown');
swoole_server_handler($serv, 'onTimer', 'my_onTimer');
swoole_server_handler($serv, 'onWorkerStart', 'my_onWorkerStart');
swoole_server_handler($serv, 'onWorkerStop', 'my_onWorkerStop');

#swoole_server_addtimer($serv, 2);
#swoole_server_addtimer($serv, 10);
swoole_server_start($serv);

