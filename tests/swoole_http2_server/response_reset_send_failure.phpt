--TEST--
swoole_http2_server: close the connection when a response reset can't be sent
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    try {
        $peer = new Http2FlowPeer($pm->getFreePort(), 65535, false, 4096);
        $peer->request(1, '/');
        Assert::true($pm->wait());
        while (($frame = @http2_test_read_frame($peer->socket)) !== false) {
            Assert::notSame($frame['type'], SWOOLE_HTTP2_TYPE_RST_STREAM);
        }
        Assert::true(feof($peer->socket));
        $peer->close();
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    http2_flow_server($pm, SWOOLE_BASE, function ($request, $response, $server) use ($pm) {
        http2_test_fill_send_buffer($server, $request->fd);
        // A synchronous callback can't wait for output buffer space
        Assert::false($response->reset());
        Assert::false($response->isWritable());
        $pm->wakeup();
    }, false, ['enable_coroutine' => false, 'send_yield' => true, 'socket_buffer_size' => 64 * 1024]);
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
