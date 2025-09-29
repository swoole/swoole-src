--TEST--
swoole_client_async: big_package_memory_leak
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set('swoole.display_errors', false);

$port = get_one_free_port();
$tcp_server = __DIR__ . "/../include/api/swoole_server/tcp_serv.php";
$closeServer = start_server($tcp_server, '127.0.0.1', $port);

$mem = memory_get_usage(true);
ini_set("memory_limit", "100m");
$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
$cli->set(['socket_buffer_size' => 2 * 1024 * 1024]);
$cli->on("connect", function (Swoole\Async\Client $cli) {
    $cli->send(str_repeat("\0", 1024 * 1024 * 1.9));
});
$cli->on("receive", function (Swoole\Async\Client $cli, $data) {
    $cli->send($data);
});
$cli->on("error", function (Swoole\Async\Client $cli) {
    echo "error";
});
$cli->on("close", function (Swoole\Async\Client $cli) use ($closeServer) {
    echo "closed\n";
    $closeServer();
});
$cli->connect('127.0.0.1', $port);
Assert::same(memory_get_usage(true), $mem);
echo "SUCCESS\n";

Swoole\Event::wait();
?>
--EXPECT--
SUCCESS
closed
