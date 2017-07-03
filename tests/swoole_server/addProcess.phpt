--TEST--
swoole_server: addProcess
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

$simple_tcp_server = __DIR__ . "/../include/apitest/swoole_server/opcode_server.php";

$port1 = get_one_free_port();
$port2 = get_one_free_port();
$port3 = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port1, "/dev/null", $port2, $port3);

suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function (\swoole_client $cli) use ($port1)
{
    $r = $cli->send(opcode_encode("addProcess", [$port1]));
    assert($r !== false);
}, function (\swoole_client $cli, $recv)
{
    list($op, $workerId) = opcode_decode($recv);
    assert($workerId !== false);
    swoole_event_exit();
    echo "SUCCESS";
});

?>
--EXPECT--
SUCCESS