--TEST--
swoole_http_client_coro: response semantics preserve header casing
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$body = 'compressed response';
$compressedBody = gzencode($body);
$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm, $body) {
    Co\run(function () use ($pm, $body) {
        foreach ([false, true] as $lowercaseHeader) {
            $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $client->set([
                'lowercase_header' => $lowercaseHeader,
                'timeout' => 2,
            ]);
            Assert::true($client->get('/'));
            Assert::same($client->body, $body);
            Assert::same($client->getCookies()['session'], 'swoole');
            Assert::same($client->set_cookie_headers, ['session=swoole; Path=/']);
            Assert::false($client->connected);

            $headers = $client->getHeaders();
            if ($lowercaseHeader) {
                Assert::keyExists($headers, 'content-encoding');
                Assert::keyExists($headers, 'set-cookie');
                Assert::keyExists($headers, 'connection');
            } else {
                Assert::keyExists($headers, 'Content-Encoding');
                Assert::keyExists($headers, 'Set-Cookie');
                Assert::keyExists($headers, 'Connection');
            }
        }
        echo "DONE\n";
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm, $compressedBody) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, int $fd) use ($compressedBody) {
        $response = "HTTP/1.1 200 OK\r\n";
        $response .= "Content-Encoding: gzip\r\n";
        $response .= "Set-Cookie: session=swoole; Path=/\r\n";
        $response .= "Connection: close\r\n";
        $response .= "Content-Length: " . strlen($compressedBody) . "\r\n\r\n";
        $server->send($fd, $response . $compressedBody);
        $server->close($fd);
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
