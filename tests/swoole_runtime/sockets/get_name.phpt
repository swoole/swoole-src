--TEST--
swoole_runtime/sockets: getsockname & getpeername
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $sock = socket_create_listen(0);
    Assert::true(socket_getsockname($sock, $server_addr, $server_port));

    go(function () use ($server_addr, $server_port) {
        $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($sock, $server_addr, $server_port);

        Assert::true(socket_getsockname($sock, $client_addr, $client_port));
        socket_send($sock, "$client_addr:$client_port", 0, 0);
        socket_recv($sock, $buf, 1024, 0);
        Assert::eq($buf, "$server_addr:$server_port");

        socket_getpeername($sock, $addr, $port);
        Assert::eq($port, $server_port);

        socket_close($sock);
    });

    $cli = socket_accept($sock);
    $data = socket_read($cli, 1024);

    Assert::true(socket_getpeername($cli, $addr, $port));
    Assert::eq($data, "$addr:$port");
    socket_write($cli, "$server_addr:$server_port");
    usleep(10000);
    socket_close($cli);
});
echo "Done\n";
?>
--EXPECT--
Done
