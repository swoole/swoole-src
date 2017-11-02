--TEST--
swoole_http_client: post without content-length

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new swoole_http_client('127.0.0.1', 9501);
    $cli->on('close', function ($cli)
    {
        echo "close\n";
    });
    $cli->post('/post', '{}', function ($cli)
    {
        assert($cli->statusCode == 200);
        assert(strlen($cli->body) > 0);
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server('127.0.0.1', 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set(['open_http_protocol' => true]);
    $serv->on('workerStart', function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });

    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $serv->send($fd,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nConnection: close\r\n\r\n{\"msg\":\"对不起,错误的请求数据.\",\"result\":2}");
        $serv->close($fd);
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
close

