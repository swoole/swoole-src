--TEST--
swoole_http_client_coro: write func 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 16;
$chunks = [];
$n = N;
while ($n--) {
    $chunks[] = base64_encode(random_bytes(random_int(256, 4096)));
}

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $chunks) {
    Co\run(function () use ($pm, $chunks) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $index = 0;
        $cli->set(['write_func' => function ($client, $data) use ($chunks, &$index) {
            Assert::eq($chunks[$index], $data);
            $index++;
            if ($index == N / 2) {
                // reset connection
                $client->close();
            }
        }]);
        Assert::false($cli->get('/'));
        Assert::eq($cli->getStatusCode(), SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
    });
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $chunks) {
    Co\run(function () use ($pm, $chunks) {
        $server = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/', function ($req, $resp) use ($server, $chunks) {
            foreach ($chunks as $chunk) {
                $resp->write($chunk);
                usleep(mt_rand(10, 50) * 1000);
            }
            $resp->end();
        });
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
