--TEST--
swoole_runtime: fclose waits for pending stream I/O to return
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--INI--
default_socket_timeout=10
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Runtime;
use SwooleTest\Assert;

function connected_streams(): array
{
    $server = stream_socket_server('tcp://127.0.0.1:0');
    Assert::resource($server);
    $client = stream_socket_client('tcp://' . stream_socket_get_name($server, false));
    Assert::resource($client);
    $peer = stream_socket_accept($server, 5);
    Assert::resource($peer);
    fclose($server);
    return [$client, $peer];
}

Runtime::enableCoroutine(SWOOLE_HOOK_TCP);
Coroutine\run(function () {
    for ($i = 0; $i < 8; ++$i) {
        [$client, $peer] = connected_streams();
        $returned = false;
        $cid = Coroutine::create(function () use ($client, &$returned) {
            Assert::false(@fread($client, 8192));
            $returned = true;
        });
        Assert::false($returned);
        Assert::true(fclose($client));
        Assert::true($returned);
        Assert::false(Coroutine::exists($cid));
        fclose($peer);
    }

    [$client, $peer] = connected_streams();
    $native = socket_import_stream($client);
    Assert::true(socket_set_option($native, SOL_SOCKET, SO_SNDBUF, 4096));
    $returned = false;
    $cid = Coroutine::create(function () use ($client, &$returned) {
        // The peer does not read, so this must remain suspended until fclose cancels it.
        $length = 16 * 1024 * 1024;
        $written = @fwrite($client, str_repeat('x', $length));
        // A send completion can win its race with cancellation, especially with Winsock buffering.
        Assert::true($written === false || (is_int($written) && $written >= 0 && $written <= $length));
        $returned = true;
    });
    Assert::false($returned);
    set_error_handler(static function (int $severity, string $message) {
        throw new RuntimeException('A closing stream must not invoke a PHP error callback: ' . $message);
    });
    try {
        Assert::true(fclose($client));
    } finally {
        restore_error_handler();
    }
    Assert::true($returned);
    Assert::false(Coroutine::exists($cid));
    unset($native);
    fclose($peer);

    $listener = stream_socket_server('tcp://127.0.0.1:0');
    $returned = false;
    $cid = Coroutine::create(function () use ($listener, &$returned) {
        Assert::false(@stream_socket_accept($listener, 10));
        $returned = true;
    });
    Assert::false($returned);
    Assert::true(fclose($listener));
    Assert::true($returned);
    Assert::false(Coroutine::exists($cid));
});
echo "DONE\n";
?>
--EXPECT--
DONE
