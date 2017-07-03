--TEST--
swoole_http_client: set cookie zval引用计数处理错误?

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

$simple_http_server = __DIR__ . "/../include/apitest/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

$cli = new \swoole_http_client(HTTP_SERVER_HOST, $port);
$cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
$cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });

function get() {
    static $i = 0;
    global $cli;
    static $zval = [
        "headers" => ["Connection" => "keep-alive"],
        "cookies" => ['name' => 'rango'],
    ];

    var_dump($cli);

    assert($cli->setCookies($zval["cookies"]));

    if ($i++ > 10) {
        echo "SUCCESS";
        swoole_event_exit();
    } else {
        if ($zval["cookies"] !== []) {
            echo "ERROR";
            swoole_event_exit();
            exit();
        }
        // var_dump($zval["cookie"]);
        // ~UNKNOWN:0 // zval 的内存错误
        $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
    }
}
get();
suicide(1000, SIGKILL, $closeServer);
swoole_event_wait();
?>

--EXPECT--
SUCCESS
