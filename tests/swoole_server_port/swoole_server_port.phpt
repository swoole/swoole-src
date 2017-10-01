--TEST--
swoole_server: swoole server port
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

 * Time: 下午4:34
 */
require_once __DIR__ . "/../include/swoole.inc";

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/multi_protocol_server.php";

$port = get_one_free_port();
$port1 = get_one_free_port();
$port2 = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port, "/dev/null", $port1, $port2);

suicide(2000);
usleep(500 * 1000);


$tokens = [1,1,1];
function checkDone()
{
    global $tokens;
    array_pop($tokens);

    if (empty($tokens)) {
        echo "SUCCESS";
        swoole_event_exit();
    }
}

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) use($port) {
    $r = $cli->send("$port\r\n");
    assert($r !== false);
}, function(\swoole_client $cli, $recv) use($port) {
    list($op, $data) = opcode_decode($recv);
    assert(intval($data) === $port);
    checkDone();
});

makeTcpClient(TCP_SERVER_HOST, $port1, function(\swoole_client $cli) use($port1) {
    $r = $cli->send("$port1\r");
    assert($r !== false);
}, function(\swoole_client $cli, $recv) use($port1) {
    list($op, $data) = opcode_decode($recv);
    assert(intval($data) === $port1);
    checkDone();
});

makeTcpClient(TCP_SERVER_HOST, $port2, function(\swoole_client $cli) use($port2) {
    $r = $cli->send("$port2\n");
    assert($r !== false);
}, function(\swoole_client $cli, $recv) use($port2) {
    list($op, $data) = opcode_decode($recv);
    assert(intval($data) === $port2);
    checkDone();
});

?>
--EXPECT--
SUCCESS