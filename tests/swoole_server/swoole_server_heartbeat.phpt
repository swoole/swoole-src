--TEST--
swoole_server: heart beat false
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

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";
$port = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) {
    $r = $cli->send(opcode_encode("heartbeat", [false]));
    assert($r !== false);
}, function(\swoole_client $cli, $recv) {
    list($op, $data) = opcode_decode($recv);
    // TODO
//    var_dump($data);

    swoole_event_exit();
    echo "SUCCESS";
});

?>
--EXPECT--
SUCCESS