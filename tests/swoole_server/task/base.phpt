--TEST--
swoole_server/task: task & finish
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

$simple_tcp_server = __DIR__ . "/../../include/api/swoole_server/tcp_task_server.php";
$port = get_one_free_port();
$closeServer = start_server($simple_tcp_server, TCP_SERVER_HOST, $port);

Co\Run(function () use($port, $closeServer) {
    $cli = new Client(SWOOLE_SOCK_TCP);
    $r = $cli->connect(TCP_SERVER_HOST, $port);
    Assert::true($r);
    $cli->send("Test swoole_server::task Interface.");
    $data = $cli->recv();
    Assert::same($data, "OK");
    $cli->close();
    Assert::false($cli->isConnected());
    echo "SUCCESS\n";
});
?>
--EXPECT--
SUCCESS
