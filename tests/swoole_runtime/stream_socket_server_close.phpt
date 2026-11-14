--TEST--
swoole_runtime: release a listening socket when it is closed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Runtime;

function listen_again(string $address): void
{
    $server = stream_socket_server('tcp://' . $address);
    Assert::resource($server);
    Coroutine::sleep(0.01);
    Assert::resource(stream_socket_client('tcp://' . $address));
    Assert::resource(stream_socket_accept($server, 1));
}

Runtime::enableCoroutine(SWOOLE_HOOK_TCP);
Coroutine\run(function () {
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $address = stream_socket_get_name($server, false);
    fclose($server);
    Assert::false(@stream_socket_client('tcp://' . $address));
    listen_again($address);

    $server = stream_socket_server('tcp://127.0.0.1:0');
    $address = stream_socket_get_name($server, false);
    Coroutine::create(function () use ($server) {
        Assert::false(@stream_socket_accept($server, 1));
    });
    fclose($server);
    listen_again($address);
});
echo "DONE\n";
?>
--EXPECT--
DONE
