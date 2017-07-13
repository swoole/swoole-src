<?php
require_once __DIR__ . "/http_server.php";


/*
class swoole_http_server extends swoole_server
{
    public swoole_function on($name, $cb) {} // 与 tcp swoole_server 的on接受的eventname 不同
}
class swoole_http_response
{
    public swoole_function cookie() {}
    public swoole_function rawcookie() {}
    public swoole_function status() {}
    public swoole_function gzip() {}
    public swoole_function header() {}
    public swoole_function write() {}
    public swoole_function end() {}
    public swoole_function sendfile() {}
}
class swoole_http_request
{
public swoole_function rawcontent() {}
}
 */

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

(new HttpServer($host, $port, true))->start();