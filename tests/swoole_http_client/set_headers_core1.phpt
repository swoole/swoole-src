--TEST--
swoole_http_client: set headers core 1

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
    global $cli;
    $cli = new \swoole_http_client("127.0.0.1", 9990);
    $cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
    $cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });

    function get() {
        static $i = 0;
        global $cli;
        $cli->setHeaders([]);
        if ($i > 10) {
            echo "SUCCESS";
            $cli->get('/shutdown', function($cli){
                $cli->close();
            });
        } else {
            $i++;
            $cli->get("/lookup?topic=worker_test", __FUNCTION__);
        }
    }
    swoole_timer_after(5000, function() { swoole_event_exit(); });
    get();
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_http_server(TCP_SERVER_HOST, 9990, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Request", function (\swoole_http_request $request, \swoole_http_response $response) use ($serv)
    {
        $uri = $request->server["request_uri"];
        if ($uri == '/shutdown')
        {
            $response->end("on");
            $serv->shutdown();
            return;
        } else {
            $response->end("SUCCESS");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>

--EXPECT--
SUCCESS
