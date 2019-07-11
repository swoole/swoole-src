--TEST--
swoole_server: exist
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

/**

 * Time: 下午4:34
 */

$simple_tcp_server = __DIR__ . "/../include/api/swoole_server/opcode_server.php";
$port = get_one_free_port();

start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

$timer = suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) {
    $r = $cli->send(opcode_encode("exist", [2]));
    Assert::assert($r !== false);
}, function(\swoole_client $cli, $recv) use ($timer){
    list($op, $data) = opcode_decode($recv);
    Assert::true($data);

    $cli->close();
    \Swoole\Timer::clear($timer);
    echo "SUCCESS\n";
});
swoole_event::wait();
?>
--EXPECT--
SUCCESS
