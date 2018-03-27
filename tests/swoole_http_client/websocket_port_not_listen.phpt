--TEST--
swoole_http_client: failure of websocket client handshake
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$cli = new swoole_http_client('127.0.0.1', 9999);
$cli->count = 0;
$cli->on('close', function ($cli)
{
    echo "close\n";
});
$cli->on('error', function ($cli)
{
    echo "error\n";
});
$cli->on('Message', function ($cli, $frame)
{
    $cli->count++;
});
$cli->upgrade('/websocket', function ($cli)
{
    @$cli->push(str_repeat('A', rand(8192, 65536)));
    assert(swoole_last_error() == 8503);
});
swoole_event::wait();
?>
--EXPECT--
error
