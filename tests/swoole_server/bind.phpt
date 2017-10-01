--TEST--
swoole_server: bind
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";
$port = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) use($port) {
    $r = $cli->send(opcode_encode("bind", [2, 42]));
    assert($r !== false);
}, function(\swoole_client $cli, $recv) {
    list($op, $binded) = opcode_decode($recv);
    assert($binded);
    swoole_event_exit();
    echo "SUCCESS";
});

?>
--EXPECT--
SUCCESS
