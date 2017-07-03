--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/6/7
 * Time: 下午4:34
 */
require_once __DIR__ . "/../include/swoole.inc";

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";

$port1 = get_one_free_port();
$port2 = get_one_free_port();
$port3 = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port1, "/dev/null", $port2, $port3);

suicide(2000);
usleep(500 * 1000);


$connected = [];
function checkDone() {
    global $connected;
    $connected[] = 1;
    if (count($connected) === 3) {
        swoole_event_exit();
        echo "SUCCESS";
    }
}


makeTcpClient(TCP_SERVER_HOST, $port1, function(\swoole_client $cli) use(&$connected) { checkDone(); });
makeTcpClient(TCP_SERVER_HOST, $port2, function(\swoole_client $cli)use(&$connected) { checkDone(); });
makeTcpClient(TCP_SERVER_HOST, $port3, function(\swoole_client $cli)use(&$connected) { checkDone(); });

?>
--EXPECT--
SUCCESS