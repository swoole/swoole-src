--TEST--
swoole_http_client_coro: skip informational responses without losing fragmented final headers or connection framing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach ([false, true] as $defer) {
            foreach (['coalesced', 'fragmented', 'eof'] as $layout) {
                $listener = http_client_body_listener($ssl);
                $interim = "HTTP/1.1 100 Continue\r\nX-Interim: ignored\r\n\r\n"
                    . "HTTP/1.1 103 Early Hints\r\nContent-Encoding: gzip\r\nSet-Cookie: interim=ignored\r\nConnection: close\r\n\r\n";
                $final = "HTTP/1.1 200 OK\r\nX-Final: retained\r\nContent-Length: 5\r\n\r\n";
                Coroutine::create(function () use ($listener, $ssl, $layout, $interim, $final) {
                    $peer = $listener->accept(5);
                    if ($ssl) {
                        Assert::true($peer->sslHandshake());
                    }
                    $buffer = '';
                    http_client_body_headers($peer, $buffer);
                    if ($layout === 'eof') {
                        $peer->sendAll($interim);
                        $peer->close();
                        return;
                    }
                    $wire = $interim . $final . 'FIRST';
                    if ($layout === 'fragmented') {
                        // Split status lines, field names, values and the final header terminator.
                        foreach (str_split($wire, 7) as $fragment) {
                            Assert::same($peer->sendAll($fragment), strlen($fragment));
                            Coroutine::sleep(0.001);
                        }
                    } else {
                        Assert::same($peer->sendAll($wire), strlen($wire));
                    }
                    http_client_body_headers($peer, $buffer);
                    http_client_body_reply($peer, 'SECOND', 200, true);
                    $peer->close();
                });
                $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                $client->set(['timeout' => 5, 'collect_stats' => true]);
                $client->setDefer($defer);
                $sent = $client->post('/first', '');
                $ok = $defer ? ($sent && $client->recv()) : $sent;
                if ($layout === 'eof') {
                    Assert::false($ok);
                    Assert::false($client->connected);
                    Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
                } else {
                    Assert::true($ok);
                    Assert::same($client->statusCode, 200);
                    Assert::same($client->body, 'FIRST');
                    Assert::true($client->connected);
                    Assert::same($client->headers['x-final'], 'retained');
                    Assert::keyNotExists($client->headers, 'x-interim');
                    Assert::keyNotExists($client->headers, 'content-encoding');
                    Assert::null($client->cookies);
                    Assert::same($client->stats['header_size'], strlen($interim) + strlen($final));
                    Assert::true($client->post('/second', ''));
                    if ($defer) {
                        Assert::true($client->recv());
                    }
                    Assert::same($client->body, 'SECOND');
                }
                $client->close();
                $listener->close();
            }
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
