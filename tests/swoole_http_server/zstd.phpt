--TEST--
swoole_http_server: support zstd compress
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use SwooleTest\ProcessManager;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

$pm = new ProcessManager();
$data = base64_encode(random_bytes(1024 * 1024));

$pm->parentFunc = function ($pid) use ($pm, $data) {
    run(function () use ($pm, $data) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->setHeaders(['Accept-Encoding' => 'zstd']);
        $client->get('/');
        Assert::true($client->body == $data);
        Assert::true($client->headers['content-encoding'] == 'zstd');
        Assert::true($client->headers['content-length'] != strlen($client->body));
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data) {
    $serv = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'compression_level' => 20
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($data) {
        $resp->end($data);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
