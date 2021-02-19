--TEST--
swoole_server: http request & response
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

define('GREETER', 'hello world');

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $httpClient = new Client(HTTP_SERVER_HOST, $pm->getFreePort(), false);
        $httpClient->setMethod("POST");
        $httpClient->setData("HELLO");
        $ok = $httpClient->execute("/rawcookie?hello=world&value=1");
        Assert::assert($ok);
        Assert::same($httpClient->statusCode, 200);
        Assert::same($httpClient->errCode, 0);
        Assert::eq($httpClient->getHeaders()['x-server'], 'swoole');
        Assert::same($httpClient->getBody(), GREETER);
        echo "DONE\n";
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http_protocol' => true,
    ]);
    $serv->on("Start", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
        $req = Request::create();
        Assert::eq($req->parse($data), strlen($data));
        
        $resp = Response::create([$serv, $req], $fd);
        $resp->header('X-Server', 'swoole');
        $resp->end(GREETER);
        Assert::eq($resp->fd, $fd);
        Assert::eq($req->fd, $fd);
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
