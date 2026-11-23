--TEST--
swoole_http_client_coro: multipart uploads preserve HTTP request headers and exact request statistics
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-multipart-stats-');
file_put_contents($file, "disk\0content");
try {
    Coroutine\run(function () use ($file) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            foreach ([false, true] as $defer) {
                foreach (['memory', 'disk', 'mixed'] as $mode) {
                    $listener = http_client_body_listener($ssl);
                    $observed = new Channel(1);
                    Coroutine::create(function () use ($listener, $ssl, $observed) {
                        $peer = $listener->accept(5);
                        if ($ssl) {
                            Assert::true($peer->sslHandshake());
                        }
                        $buffer = '';
                        $request = http_client_body_headers($peer, $buffer);
                        http_client_body_digest($peer, $buffer, $request['length']);
                        $observed->push($request);
                        http_client_body_reply($peer, 'multipart');
                        $request = http_client_body_headers($peer, $buffer);
                        Assert::same($request['length'], 2);
                        http_client_body_digest($peer, $buffer, 2);
                        $observed->push($request);
                        http_client_body_reply($peer, 'raw', 200, true);
                        $peer->close();
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5, 'collect_stats' => true]);
                    $client->setDefer($defer);
                    $client->setMethod('POST');
                    $client->setData(['field' => 'value']);
                    if ($mode !== 'disk') {
                        $client->addData("memory\0content", 'memory');
                        $client->addData('', 'empty');
                    }
                    if ($mode !== 'memory') {
                        $client->addFile($file, 'disk');
                    }
                    foreach (['/multipart', '/raw'] as $path) {
                        Assert::true($path === '/raw' ? $client->post($path, 'ok') : $client->execute($path));
                        if ($defer) {
                            Assert::true($client->recv());
                        }
                        $request = $observed->pop(5);
                        Assert::same($client->getHeaderOut(), $request['header']);
                        Assert::same($client->stats['upload_content_length'], $request['length']);
                        Assert::same($client->stats['size_upload'], $request['length']);
                        Assert::same($client->stats['request_size'], strlen($request['header']) + 4 + $request['length']);
                    }
                    $client->close();
                    Assert::same($client->getHeaderOut(), $request['header']);
                    $listener->close();
                }
            }
        }
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
