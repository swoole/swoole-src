--TEST--
swoole_runtime: stream_socket_recvfrom honors nonblocking mode and zero timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Runtime;
use SwooleTest\Assert;

Assert::setThrowException(true);
Runtime::enableCoroutine(SWOOLE_HOOK_UDP);

Coroutine\run(function () {
    $receiver = stream_socket_server('udp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND);
    $sender = stream_socket_server('udp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND);
    Assert::true(is_resource($receiver) && is_resource($sender));
    $target = stream_socket_get_name($receiver, false);
    $source = stream_socket_get_name($sender, false);

    foreach ([false, true] as $blocked) {
        Assert::true(stream_set_blocking($receiver, $blocked));
        Assert::true(stream_set_timeout($receiver, 0, $blocked ? 0 : 100000));
        $sent = new Channel(1);
        Coroutine::create(static function () use ($sender, $target, $sent) {
            Coroutine::sleep(0.01);
            $sent->push(stream_socket_sendto($sender, 'ping', 0, $target));
        });

        // Any read that suspends can receive the delayed packet instead of returning false.
        Assert::false(stream_socket_recvfrom($receiver, 16));
        Assert::false(stream_socket_recvfrom($receiver, 16, 0, $peer));
        Assert::null($peer);
        Assert::false(stream_socket_recvfrom($receiver, 16, STREAM_PEEK, $peer));
        Assert::null($peer);
        $meta = stream_get_meta_data($receiver);
        Assert::same($meta['blocked'], $blocked);
        Assert::false($meta['timed_out']);
        Assert::false($meta['eof']);

        Assert::same($sent->pop(1), 4);
        Assert::same(stream_socket_recvfrom($receiver, 16, STREAM_PEEK), 'ping');
        Assert::same(stream_socket_recvfrom($receiver, 16, STREAM_PEEK, $peer), 'ping');
        Assert::same($peer, $source);
        Assert::same(stream_socket_recvfrom($receiver, 16, 0, $peer), 'ping');
        Assert::same($peer, $source);
    }

    fclose($sender);
    fclose($receiver);
});

Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
