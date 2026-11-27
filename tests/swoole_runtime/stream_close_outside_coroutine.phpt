--TEST--
swoole_runtime: fclose outside a coroutine drains pending stream reads
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Runtime;
use SwooleTest\Assert;

Runtime::enableCoroutine(SWOOLE_HOOK_TCP);
swoole_async_set(['enable_coroutine' => false]);
Coroutine\run(function () {
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $client = stream_socket_client('tcp://' . stream_socket_get_name($server, false));
    $peer = stream_socket_accept($server, 5);
    fclose($server);
    $returned = false;
    $cid = Coroutine::create(function () use ($client, &$returned) {
        Assert::false(@fread($client, 8192));
        $returned = true;
    });
    Assert::false($returned);
    // Event callbacks have no current coroutine; close must process native completions directly.
    Swoole\Event::defer(function () use ($client, $peer, $cid, &$returned) {
        Assert::same(Coroutine::getCid(), -1);
        Assert::true(fclose($client));
        Assert::true($returned);
        Assert::false(Coroutine::exists($cid));
        fclose($peer);
    });
});
echo "DONE\n";
?>
--EXPECT--
DONE
