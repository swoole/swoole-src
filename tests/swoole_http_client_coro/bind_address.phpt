--TEST--
swoole_http_client_coro: bind local addresses and recover from invalid binding settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        foreach ([get_one_free_port(), -1, null] as $port) {
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $settings = ['bind_address' => '127.0.0.1'];
            if ($port !== null) {
                $settings['bind_port'] = $port;
            }
            Assert::true($client->set($settings));
            Assert::true($client->post('/', ['bind_port' => $port ?? 0]));
            Assert::same($client->statusCode, 200);
            Assert::same($client->body, 'OK');
            $client->close();
        }

        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->set(['bind_address' => 11111]));
        try {
            $client->get('/');
            Assert::true(false, 'invalid bind address must throw');
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
            Assert::contains($exception->getMessage(), 'failed to bind socket');
        }
        Assert::false($client->connected);
        Assert::true($client->set(['bind_address' => '127.0.0.1']));
        Assert::true($client->get('/'));
        Assert::same($client->body, 'OK');
        $client->close();

        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/stop'));
        Assert::same($client->body, 'STOP');
        $client->close();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/', function ($request, $response) {
            Assert::same($request->server['remote_addr'], '127.0.0.1');
            $port = $request->post['bind_port'] ?? null;
            if ($port !== null && (int) $port > 0) {
                Assert::same($request->server['remote_port'], (int) $port);
            } else {
                Assert::greaterThan($request->server['remote_port'], 0);
            }
            $response->end('OK');
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end('STOP');
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
