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
use Swoole\Coroutine\WaitGroup;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $wg = new WaitGroup();

        $wg->add(5);
        //test1: valid address
        go(function () use ($pm, $wg) {
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $bindAddress = current(swoole_get_local_ip());
            $bindPort = get_one_free_port();

            $client->set([
                'bind_address' => $bindAddress,
                'bind_port' => $bindPort,
            ]);
            $client->post('/validaddress', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);
            $wg->done();
        });

        // test2: invalid address
        go(function () use ($pm, $wg) {
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $bindAddress = 11111;
            $bindPort = get_one_free_port();

            $client->set([
                'bind_address' => $bindAddress,
                'bind_port' => $bindPort,
            ]);
            $client->post('/invalidaddress', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);
            $wg->done();
        });

        // test3: invalid port
        go(function () use ($pm, $wg) {
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $bindAddress = current(swoole_get_local_ip());
            $bindPort = -1;

            $client->set([
                'bind_address' => $bindAddress,
                'bind_port' => -1,
            ]);
            $client->post('/invalidport', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);
            $wg->done();
        });

        // test4: not bind port
        go(function () use ($pm, $wg) {
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $bindAddress = current(swoole_get_local_ip());
            $bindPort = null;

            $client->set([
                'bind_address' => $bindAddress,
            ]);
            $client->post('/notbindport', ['bind_address' => $bindAddress, 'bind_port' => $bindPort]);
            $wg->done();
        });

        //test5: request baidu.com
        go(function () use ($pm, $wg) {
            $client = new Client('www.baidu.com', 80);
            $bindAddress = current(swoole_get_local_ip());
            $bindPort = get_one_free_port();

            $client->set([
                'bind_address' => $bindAddress,
                'bind_port' => $bindPort,
            ]);
            Assert::true($client->get('/'));

            $client = new Client('www.baidu.com', 80);
            $bindAddress = '127.0.0.1';
            $bindPort = get_one_free_port();

            $client->set([
                'bind_address' => $bindAddress,
                'bind_port' => $bindPort,
            ]);
            Assert::false($client->get('/'));
            $wg->done();
        });

        $wg->wait();
        
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->get('/stop?hello=1');
        echo $client->body . PHP_EOL;
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
