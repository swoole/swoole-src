--TEST--
swoole_http_client_coro: response headers are always lowercase, including legacy false settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Assert::false(defined('Swoole\\Constant::OPTION_LOWERCASE_HEADER'));
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach ([[], ['lowercase_header' => false]] as $settings) {
            $listener = http_client_body_listener($ssl);
            $compressed = defined('SWOOLE_HAVE_ZLIB') && function_exists('gzencode');
            Coroutine::create(function () use ($listener, $ssl, $compressed) {
                $peer = $listener->accept(5);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                http_client_body_headers($peer, $buffer);
                $body = $compressed ? gzencode('decoded') : 'decoded';
                $encoding = $compressed ? "Content-Encoding: gzip\r\n" : '';
                $response = "HTTP/1.1 200 OK\r\nHello-World: value\r\nSet-Cookie: session=abc\r\n"
                    . $encoding . "Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
                Assert::same($peer->sendAll($response), strlen($response));
                $peer->close();
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set($settings + ['timeout' => 5]);
            Assert::true($client->post('/', ''));
            Assert::same($client->body, 'decoded');
            Assert::same($client->cookies['session'], 'abc');
            Assert::same($client->headers['hello-world'], 'value');
            foreach (array_keys($client->headers) as $name) {
                Assert::same($name, strtolower($name));
            }
            $client->close();
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
