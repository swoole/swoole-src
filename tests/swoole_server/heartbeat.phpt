--TEST--
swoole_server: heart beat false
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";
$port = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

$timer = suicide(2000);
usleep(200 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function (\swoole_client $cli) {
    $r = $cli->send(opcode_encode("heartbeat", [false]));
    Assert::assert($r !== false);
}, function (\swoole_client $cli, $recv) use ($timer) {
    list($op, $data) = opcode_decode($recv);

    $cli->close();
    swoole_timer::clear($timer);
    echo "SUCCESS\n";
});
swoole_event::wait();
?>
--EXPECT--
SUCCESS
