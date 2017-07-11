--TEST--
swoole_http_client: setHeaders & setCookies

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

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

$cli = new \swoole_http_client(HTTP_SERVER_HOST, $port);
$cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
$cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });

function get() {
    static $i = 0;
    global $cli;
    static $zval = [
        "headers" => ["Connection" => "keep-alive"],
        "cookies" => ['name' => 'rango', 'value' => 1234],
    ];

    assert($cli->setCookies($zval["cookies"]));

    if ($i++ > 10)
    {
        echo "SUCCESS\n";
        $cli->close();
    }
    else
    {
        assert($zval["cookies"]['name'] == 'rango');
        assert($zval["cookies"]['value'] == '1234');
        $cli->get("/test", __FUNCTION__);
    }
}
get();
suicide(1000, SIGKILL, $closeServer);
swoole_event_wait();
?>

--EXPECT--
SUCCESS
