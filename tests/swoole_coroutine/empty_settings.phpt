--TEST--
swoole_coroutine: empty settings are accepted and empty option arrays clear their values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
$http = new Swoole\Coroutine\Http\Client('127.0.0.1', 1);
Assert::true($http->set([]));
Assert::true($http->set(['timeout' => 2]));
Assert::true($http->set([]));
Assert::same($http->setting['timeout'], 2);
Assert::true($http->setHeaders(['X-Test' => 'value']));
Assert::true($http->setHeaders([]));
Assert::null($http->headers);

$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
Assert::true($client->set([]));
Assert::true($client->set(['timeout' => 2]));
Assert::true($client->set([]));
Assert::same($client->setting['timeout'], 2);

Swoole\Coroutine\run(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->setProtocol([]));
    $socket->close();

    $server = new Swoole\Coroutine\Http\Server('127.0.0.1', 0);
    Assert::true($server->set([]));
    $server->handle('/', static function ($request, $response) {
        $response->end('OK');
    });
    $cid = Swoole\Coroutine::create(static fn () => $server->start());
    try {
        foreach ([null, [], ['timeout' => 2]] as $options) {
            $response = Swoole\Coroutine\Http\get("http://127.0.0.1:{$server->port}/", $options);
            Assert::same($response->getStatusCode(), 200);
            Assert::same($response->getBody(), 'OK');
        }
    } finally {
        $server->shutdown();
        Swoole\Coroutine::join([$cid]);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
