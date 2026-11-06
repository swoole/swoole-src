--TEST--
swoole_runtime: zero timeout streams recover without retaining another operation's errno
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
Swoole\Coroutine\run(function () {
    [$stream, $peer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    [$other, $otherPeer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    stream_set_timeout($other, 0, 10000);

    foreach (['r', 's'] as $byte) {
        stream_set_timeout($stream, 0, 10000);
        Assert::false(@fread($stream, 1));
        Assert::true(stream_get_meta_data($stream)['timed_out']);
        Assert::false(stream_get_meta_data($stream)['eof']);

        stream_set_timeout($stream, 0, 0);
        Assert::false(stream_get_meta_data($stream)['timed_out']);
        Assert::same(fwrite($peer, $byte), 1);

        // Leave ETIMEDOUT in errno after the target stream's timeout option was set.
        // A successful recv_once must not copy that unrelated error into the stream.
        Assert::false(@fread($other, 1));
        Assert::same(fread($stream, 1), $byte);
        Assert::false(stream_get_meta_data($stream)['timed_out']);
        Assert::false(stream_get_meta_data($stream)['eof']);

        Assert::false(@fread($other, 1));
        Assert::same(fread($stream, 1), '');
        Assert::false(stream_get_meta_data($stream)['timed_out']);
        Assert::false(stream_get_meta_data($stream)['eof']);

        // The same errno rule applies to an immediate successful write.
        Assert::false(@fread($other, 1));
        Assert::same(fwrite($stream, $byte), 1);
        Assert::false(stream_get_meta_data($stream)['timed_out']);
        Assert::same(fread($peer, 1), $byte);
    }

    fclose($peer);
    Assert::same(fread($stream, 1), '');
    Assert::true(stream_get_meta_data($stream)['eof']);
    fclose($stream);
    fclose($other);
    fclose($otherPeer);
});
echo "OK\n";
?>
--EXPECT--
OK
