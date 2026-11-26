--TEST--
swoole_http_client_coro: reject new requests while a deferred response is pending
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use SwooleTest\Assert;

Assert::setThrowException(true);

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $requests = [];
    $server->handle('/', function ($request, $response) use (&$requests) {
        $path = $request->server['request_uri'];
        $requests[] = [$request->server['request_method'], $path];
        $response->end($path);
    });
    Coroutine::create(fn () => $server->start());

    $client = new Client('127.0.0.1', $server->port);
    $body = '';
    $client->set(['timeout' => 2, 'write_func' => function (Client $client, string $data) use (&$body) {
        Assert::false($client->execute('/from-callback'));
        Assert::same($client->statusCode, 200);
        $body .= $data;
    }]);
    $client->setDefer(true);
    try {
        Assert::true($client->get('/first'));
        Assert::false($client->post('/extra-post', 'ignored'));
        Assert::false($client->download('/extra-download', __FILE__ . '.download'));
        Assert::false($client->upgrade('/extra-upgrade'));
        Assert::notSame($client->errCode, 0);
        Assert::same($client->requestMethod, 'GET');
        Assert::null($client->requestBody);
        Assert::null($client->downloadFile);
        Assert::null($client->requestHeaders);
        Assert::true($client->getDefer());

        Assert::true($client->recv());
        Assert::same($body, '/first');
        Assert::true($client->get('/second'));
        Assert::true($client->recv());
        Assert::same($body, '/first/second');
        Assert::same($requests, [['GET', '/first'], ['GET', '/second']]);
    } finally {
        $client->close();
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
