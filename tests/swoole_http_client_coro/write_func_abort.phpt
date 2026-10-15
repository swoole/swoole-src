--TEST--
swoole_http_client_coro: write_func can abort with false and preserve legacy return values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $chunks = [str_repeat('a', 32), str_repeat('b', 32), str_repeat('c', 32)];
    $server->handle('/', function ($request, $response) use ($chunks) {
        foreach ($chunks as $chunk) {
            if (!$response->write($chunk)) {
                return;
            }
            Coroutine::sleep(0.02);
        }
        $response->end();
    });
    Coroutine::create(fn () => $server->start());
    try {
        foreach ([1, 2] as $abortAt) {
            $calls = 0;
            $body = '';
            $abort = true;
            $client = new Client('127.0.0.1', $server->port);
            $client->set(['timeout' => 2, 'write_func' => function ($client, $data) use (&$calls, &$body, &$abort, $abortAt) {
                $body .= $data;
                $calls++;
                if ($abort && $calls === $abortAt) {
                    return false;
                }
                // Existing callbacks often have no return value.
            }]);
            if ($client->get('/') !== false || $calls !== $abortAt || $client->connected
                || $client->statusCode !== SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET || $client->errCode === 0
                || $body !== implode('', array_slice($chunks, 0, $abortAt))) {
                throw new RuntimeException('write_func did not abort reception');
            }
            $abort = false;
            $calls = 0;
            $body = '';
            if (!$client->get('/') || $body !== implode('', $chunks)
                || $client->statusCode !== 200 || $client->errCode !== 0) {
                throw new RuntimeException('Aborted client could not be reused');
            }
            $client->close();
        }
        // Only false aborts: null, zero and other old return values remain compatible.
        foreach ([null, 0, true, 32, 'ignored', ['ignored']] as $returnValue) {
            $body = '';
            $client = new Client('127.0.0.1', $server->port);
            $client->set(['timeout' => 2, 'write_func' => function ($client, $data) use ($returnValue, &$body) {
                if ($client->statusCode !== 200) {
                    throw new RuntimeException('Response status was unavailable in write_func');
                }
                $body .= $data;
                return $returnValue;
            }]);
            if (!$client->get('/') || $body !== implode('', $chunks)) {
                throw new RuntimeException('Legacy write_func return value aborted reception');
            }
            $client->close();
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
