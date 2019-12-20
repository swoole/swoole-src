--TEST--
swoole_http2_server_coro: cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();
        $requests = [];
        for ($n = MAX_REQUESTS; $n--;) {
            $request = new Swoole\Http2\Request;
            $request->headers = ['id' => $n];
            $request->cookies = [];
            for ($k = 32; $k--;) {
                $request->cookies[get_safe_random()] = get_safe_random();
            }
            $requests[$n] = $request;
            Assert::assert($cli->send($request));
        }
        for ($n = MAX_REQUESTS; $n--;) {
            $response = $cli->recv(1);
            if (Assert::isInstanceOf($response, Swoole\Http2\Response::class)) {
                $request = $requests[$response->headers['id']];
                Assert::same('OK', $response->data);
                Assert::same($request->cookies, $response->cookies);
            }
        }
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        Coroutine::create(function () use ($pm) {
            $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
            $http->set([
                'log_file' => '/dev/null',
                'open_http2_protocol' => true
            ]);
            $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
                $response->header('id', $request->header['id']);
                foreach ($request->cookie as $name => $value) {
                    $response->cookie($name, $value);
                }
                $response->end('OK');
            });
            $http->start();
        });
    });
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
DONE
