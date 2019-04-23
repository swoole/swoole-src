--TEST--
swoole_server: get client info
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

suicide(2000);
usleep(500 * 1000);

makeTcpClient(TCP_SERVER_HOST, $port, function(\swoole_client $cli) {
    $r = $cli->send(opcode_encode("getClientInfo", [2]));
    Assert::assert($r !== false);
}, function(\swoole_client $cli, $recv) {
    list($op, $data) = opcode_decode($recv);
    Assert::assert(is_array($data) && $data);
    /**
     *
    array(8) {
    ["server_fd"]=>
    int(3)
    ["socket_type"]=>
    int(1)
    ["server_port"]=>
    int(49749)
    ["remote_port"]=>
    int(49758)
    ["remote_ip"]=>
    string(9) '127.0.0.1'
    ["from_id"]=>
    int(1)
    ["connect_time"]=>
    int(1496842883)
    ["last_time"]=>
    int(1496842884)
    }
     */
    swoole_event_exit();
    echo "SUCCESS";
});

?>
--EXPECT--
SUCCESS