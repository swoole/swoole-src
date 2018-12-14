--TEST--
swoole_mysql_coro: mysql client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $data = curlGet("http://127.0.0.1:{$pm->getFreePort()}/");
    echo $data;
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(array(
        'log_file' => '/dev/null'
    ));
    $http->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response)
    {
        $mysql = new Swoole\Coroutine\MySQL();
        $res = $mysql->connect([
            'host' => MYSQL_SERVER_HOST,
            'user' => MYSQL_SERVER_USER,
            'password' => MYSQL_SERVER_PWD,
            'database' => MYSQL_SERVER_DB
        ]);
        if (!$res)
        {
            fail:
            $response->end("ERROR\n");
            return;
        }
        $ret = $mysql->query('show tables', 2);
        if (!$ret) {
            goto fail;
        }
        if (count($ret) > 0) {
            $response->end("OK\n");
        }
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
