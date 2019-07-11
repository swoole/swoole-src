--TEST--
swoole_client_async: big_package_memory_leak
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set('swoole.display_errors', false);

$tcp_server = __DIR__ . "/../include/api/swoole_server/tcp_serv.php";
$closeServer = start_server($tcp_server, '127.0.0.1', 9001);

$mem = memory_get_usage(true);
ini_set("memory_limit", "100m");
$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->set(['socket_buffer_size' => 2 * 1024 * 1024]);
$cli->on("connect", function (swoole_client $cli) {
    $cli->send(str_repeat("\0", 1024 * 1024 * 1.9));
});
$cli->on("receive", function (swoole_client $cli, $data) {
    $cli->send($data);
});
$cli->on("error", function (swoole_client $cli) {
    echo "error";
});
$cli->on("close", function (swoole_client $cli) use ($closeServer) {
    echo "closed\n";
    $closeServer();
});
$cli->connect('127.0.0.1', 9001);
Assert::same(memory_get_usage(true), $mem);
echo "SUCCESS\n";

swoole_event::wait();
?>
--EXPECT--
SUCCESS
closed
