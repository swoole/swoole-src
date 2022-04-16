--TEST--
swoole_http_server: slow client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->connect("127.0.01", $pm->getFreePort());
    $html = base64_encode(random_bytes(rand(1024, 65536)));
    $len = strlen($html);
    $data = "POST /index.html HTTP/1.1\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: $len\r\nX-Server: swoole\r\n\r\n$html";
    $chunks = str_split($data, rand(5, 255));
    foreach ($chunks as $out) {
        $client->send($out);
        usleep(100);
    }

    $data = $client->recv();
    Assert::stringNotEmpty($data);
    Assert::true(swoole_string($data)->contains('HTTP/1.1 200 OK'));
    $pm->kill();
    echo "OK\n";
};

$pm->childFunc = function () use ($pm)
{
    $http = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);

    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (Request $request, Response $response) {
        Assert::same($request->header['server'], 'nginx');
        Assert::same($request->header['x-server'], 'swoole');
        Assert::same($request->header['content-type'], 'text/html');
        Assert::eq($request->header['content-length'], strlen($request->getContent()));
        $response->end("OK");
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
