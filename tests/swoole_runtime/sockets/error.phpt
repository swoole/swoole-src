--TEST--
swoole_runtime/sockets: error
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

$port = get_one_free_port();

run(function () use($port) {
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($sock, '127.0.0.1', $port);

    Assert::eq(socket_last_error(), SOCKET_ECONNREFUSED);
    Assert::eq(socket_last_error(), socket_last_error($sock));

    socket_clear_error();
    Assert::eq(socket_last_error(), 0);
    Assert::eq(socket_last_error($sock), SOCKET_ECONNREFUSED);
    socket_clear_error($sock);
    Assert::eq(socket_last_error($sock), 0);
});
echo "Done\n";
?>
--EXPECT--
Done
