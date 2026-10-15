--TEST--
swoole_http_client_coro: fragmented compressed callbacks preserve keep-alive and respect body_decompression
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('zlib');
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/http_compression_fixture.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Assert::setThrowException(true);
Coroutine\run(function () {
    [$expected, $encoded] = http_compression_fixture();
    $server = new Server('127.0.0.1', 0);
    $server->set(['http_compression' => false]);
    $server->handle('/', function ($request, $response) use ($expected, $encoded) {
        $encoding = $request->get['encoding'];
        $wire = $encoding === 'identity' ? $expected : $encoded[$encoding];
        if (isset($request->get['empty'])) {
            $wire = gzencode('');
        }
        if ($encoding !== 'identity') {
            $response->header('Content-Encoding', $encoding);
        }
        $response->header('X-Peer-Port', (string) $request->server['remote_port']);
        // One-byte HTTP chunks split compression headers, data and trailers independently.
        foreach (str_split($wire) as $byte) {
            if (!$response->write($byte)) {
                return;
            }
        }
        $response->end();
    });
    $cid = Coroutine::create(fn () => $server->start());
    $received = '';
    $calls = 0;
    $client = new Client('127.0.0.1', $server->port);
    $client->set(['timeout' => 3, 'write_func' => function ($client, $chunk) use (&$received, &$calls) {
        Assert::notSame($chunk, '', 'Compression headers and trailers must not cause empty callbacks');
        $received .= $chunk;
        $calls++;
    }]);
    $peerPort = null;
    try {
        foreach ($encoded as $encoding => $wire) {
            $client->setHeaders(['Accept-Encoding' => $encoding]);
            foreach ([true, false, true] as $decode) {
                $received = '';
                $calls = 0;
                Assert::true($client->set(['body_decompression' => $decode]));
                Assert::true($client->get('/?encoding=' . $encoding));
                Assert::same($received, $decode ? $expected : $wire);
                Assert::greaterThan($calls, 0);
                Assert::same($client->body, '');
                Assert::same($client->statusCode, 200);
                Assert::same($client->errCode, 0);
                Assert::same($client->headers['content-encoding'], $encoding);
                Assert::same($client->headers['transfer-encoding'], 'chunked');
                $peerPort ??= $client->headers['x-peer-port'];
                Assert::same($client->headers['x-peer-port'], $peerPort);
            }
        }
        // An uncompressed response on the same connection must not reuse the previous decoder.
        $received = '';
        $calls = 0;
        $client->set(['body_decompression' => true]);
        Assert::true($client->get('/?encoding=identity'));
        Assert::same($received, $expected);
        Assert::greaterThan($calls, 0);
        Assert::keyNotExists($client->headers, 'content-encoding');
        Assert::same($client->body, '');
        Assert::same($client->headers['x-peer-port'], $peerPort);

        foreach ([true, false, true] as $decode) {
            $received = '';
            $calls = 0;
            $client->set(['body_decompression' => $decode]);
            Assert::true($client->get('/?encoding=gzip&empty=1'));
            Assert::same($received, $decode ? '' : gzencode(''));
            Assert::same($calls === 0, $decode);
            Assert::same($client->body, '');
            Assert::same($client->headers['x-peer-port'], $peerPort);
        }
    } finally {
        $client->close();
        // Drain accepted connections before releasing the listener's callback on stable branches.
        $handlers = array_values(array_diff(iterator_to_array(Coroutine::list()), [Coroutine::getCid(), $cid]));
        if ($handlers) {
            Assert::true(Coroutine::join($handlers, 3));
        }
        $server->shutdown();
        Coroutine::join([$cid]);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
