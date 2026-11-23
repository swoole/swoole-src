--TEST--
swoole_http_client_coro: detach shared request arrays before adding uploads, cookies or upgrade headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-upload-cow-');
file_put_contents($file, 'contents');
try {
    Coroutine\run(function () use ($file) {
        foreach (['addData', 'addFile'] as $method) {
            $client = new Client('127.0.0.1', 1);
            $client->uploadFiles = [];
            Assert::true($client->$method($method === 'addFile' ? $file : 'contents', 'first'));
            $snapshot = $client->uploadFiles;
            Assert::true($client->$method($method === 'addFile' ? $file : 'contents', 'second'));
            Assert::count($snapshot, 1);
            Assert::count($client->uploadFiles, 2);
            Assert::same($snapshot[0]['name'], 'first');
        }
        foreach ([[], ['X-Original' => 'value']] as $headers) {
            $client = new Client('127.0.0.1', 1);
            $client->set(['timeout' => 0.1]);
            $client->setHeaders($headers);
            $snapshot = $client->requestHeaders;
            Assert::false($client->upgrade('/'));
            Assert::same($snapshot, $headers);
            Assert::same($client->requestHeaders['Upgrade'], 'websocket');
        }
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            $listener = http_client_body_listener($ssl);
            Coroutine::create(function () use ($listener, $ssl) {
                $peer = $listener->accept(5);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                http_client_body_headers($peer, $buffer);
                $peer->sendAll("HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\nSet-Cookie: user=two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                $peer->close();
            });
            $cookies = ['user' => 'one'];
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->setCookies($cookies);
            $snapshot = $client->cookies;
            Assert::true($client->post('/', ''));
            Assert::same($cookies, ['user' => 'one']);
            Assert::same($snapshot, $cookies);
            Assert::same($client->cookies, ['user' => 'two', 'session' => 'abc']);
            $client->close();
            $listener->close();
        }
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
