--TEST--
swoole_http_client: recursive_get

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

$cli = new \swoole_http_client("127.0.0.1", 80);
$cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
$cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });
$i = 0;
function get() {
    global $cli, $i;
    ++$i;
    $cli->get("/", __FUNCTION__);
}
get();
swoole_timer_after(1000, function() use(&$i) {
    if ($i > 10) {
        echo "SUCCESS";
    } else {
        echo "ERROR";
    }
    swoole_event_exit();
});
swoole_event_wait();
?>

--EXPECT--
SUCCESS
