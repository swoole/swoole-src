--TEST--
swoole_http_client_coro: bind address and port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        //test1: valid address
        $client1 = new Client('127.0.0.1', $pm->getFreePort());
        $bindAddress = current(swoole_get_local_ip());
        $bindPort = get_one_free_port();

        $client1->set([
            'bind_address' => $bindAddress,
            'bind_port' => $bindPort,
        ]);
        $client1->post('/validaddress', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);

        // test2: invalid address
        $client2 = new Client('127.0.0.1', $pm->getFreePort());
        $bindAddress = 11111;
        $bindPort = get_one_free_port();

        $client2->set([
            'bind_address' => $bindAddress,
            'bind_port' => $bindPort,
        ]);
        $client2->post('/invalidaddress', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);

        // test3: invalid port
        $client3 = new Client('127.0.0.1', $pm->getFreePort());
        $bindAddress = current(swoole_get_local_ip());
        $bindPort = -1;

        $client3->set([
            'bind_address' => $bindAddress,
            'bind_port' => -1,
        ]);
        $client3->post('/invalidport', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);

        // test4: not bind port
        $client4 = new Client('127.0.0.1', $pm->getFreePort());
        $bindAddress = current(swoole_get_local_ip());
        $bindPort = null;

        $client4->set([
            'bind_address' => $bindAddress,
        ]);
        $client4->post('/notbindport', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);

        $client1->get('/stop?hello=1');
        echo $client1->body . PHP_EOL;
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/validaddress', function (Request $request, Response $response) {
            Assert::eq($request->server['remote_addr'], $request->post['bind_address']);
            Assert::eq($request->server['remote_port'], $request->post['bind_port']);
        });
        $server->handle('/invalidaddress', function (Request $request, Response $response) {
            Assert::eq($request->post['bind_address'], '11111');
            Assert::eq($request->server['remote_addr'], '127.0.0.1');
            Assert::eq($request->server['remote_port'], $request->post['bind_port']);
        });
        $server->handle('/invalidport', function (Request $request, Response $response) {
            Assert::eq($request->post['bind_port'], '-1');
            Assert::eq($request->server['remote_addr'], $request->post['bind_address']);
            Assert::greaterThan($request->server['remote_port'], 0);
        });
        $server->handle('/notbindport', function (Request $request, Response $response) {
            Assert::keyNotExists($request->post, 'bind_port');
            Assert::eq($request->server['remote_addr'], $request->post['bind_address']);
            Assert::greaterThan($request->server['remote_port'], 0);
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end("<h1>Stop</h1>");
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
<h1>Stop</h1>
DONE
