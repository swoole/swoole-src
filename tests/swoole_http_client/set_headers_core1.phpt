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

$cli = new \swoole_http_client("127.0.0.1", 4161);
$cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
$cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });

function get() {
    static $i = 0;
    global $cli;
    $cli->setHeaders([]);
    if ($i > 10) {
        echo "SUCCESS";
    } else {
        $i++;
        $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
    }
}
swoole_timer_after(5000, function() { swoole_event_exit(); });
get();
swoole_event_wait();
?>

--EXPECT--
SUCCESS
