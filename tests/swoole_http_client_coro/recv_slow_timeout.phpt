--TEST--
swoole_http_client_coro: recv_all data from slow server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_LOW; $c--;) {
        go(function () use ($pm) {
            $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 1]);
            $s = microtime(true);
            $ret = $cli->get('/');
            $s = microtime(true) - $s;
            phpt_var_dump($s);
            if (Assert::assert(!$ret)) {
                Assert::assert($cli->errCode === SOCKET_ETIMEDOUT);
                Assert::assert($cli->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
                time_approximate(1, $s);
            }
            $cli->close();
        });
    }
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::assert($server->bind('127.0.0.1', $pm->getFreePort()));
        Assert::assert($server->listen());
        while ($client = $server->accept()) {
            go(function () use ($server, $client) {
                Assert::assert($client instanceof Swoole\Coroutine\Socket);
                $data =
                    "HTTP/1.1 200 OK\r\n" .
                    "Connection: keep-alive\r\n" .
                    "Server: gunicorn/19.9.0\r\n" .
                    "Date: Wed, 26 Dec 2018 23:56:51 GMT\r\n" .
                    "Content-Type: text/html; charset=utf-8\r\n" .
                    "Content-Length: 10122\r\n" .
                    "Access-Control-Allow-Origin: *\r\n" .
                    "Access-Control-Allow-Credentials: true\r\n" .
                    "Via: 1.1 vegur\r\n" .
                    "\r\n";
                for ($n = 0; $n < strlen($data); $n++) {
                    var_dump_return("send {$n}\n");
                    $client->send($data[$n]);
                    usleep(mt_rand(10, 800) * 1000);
                }
            });
        }
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
