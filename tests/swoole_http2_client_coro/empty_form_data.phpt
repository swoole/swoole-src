--TEST--
swoole_http2_client_coro: an empty encoded form ends the request without leaking a stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use SwooleTest\Assert;

Assert::setThrowException(true);
function readFormFrame(Socket $peer): array
{
    $header = $peer->recvAll(9, 2);
    Assert::same(strlen($header), 9);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $payload = $length ? $peer->recvAll($length, 2) : '';
    Assert::same(strlen($payload), $length);
    return [ord($header[3]), ord($header[4]), unpack('N', substr($header, 5, 4))[1], $payload];
}
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    Assert::same(readFormFrame($peer)[0], SWOOLE_HTTP2_TYPE_SETTINGS);
    $settings = http2_test_frame(4, 0, 0);
    Assert::same($peer->sendAll($settings), strlen($settings));
    try {
        foreach ([false, true] as $pipeline) {
            foreach ([[], ['field' => null], ['nested' => []], ['field' => null, 'nested' => []], ['field' => 'value']] as $data) {
                $expected = http_build_query($data);
                $request = new Request();
                $request->method = 'POST';
                $request->data = $data;
                $request->pipeline = $pipeline;
                $id = $client->send($request);
                Assert::greaterThan($id, 0);
                [$type, $flags, $stream] = readFormFrame($peer);
                Assert::same($type, SWOOLE_HTTP2_TYPE_HEADERS);
                Assert::same($stream, $id);
                Assert::same((bool) ($flags & 1), $expected === '' && !$pipeline);
                if ($expected !== '') {
                    Assert::same(readFormFrame($peer), [0, $pipeline ? 0 : 1, $id, $expected]);
                }
                if ($pipeline) {
                    Assert::true($client->write($id, ['end' => null], true));
                    Assert::same(readFormFrame($peer), [0, 1, $id, '']);
                }
                $response = http2_test_frame(1, 5, $id, "\x88");
                Assert::same($peer->sendAll($response), strlen($response));
                Assert::same($client->recv(2)->streamId, $id);
                Assert::same($client->stats('active_stream_num'), 0);
                if ($id === 1) {
                    Assert::same(array_slice(readFormFrame($peer), 0, 2), [4, 1]);
                }
            }
        }
    } finally {
        $client->close();
        $peer->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
