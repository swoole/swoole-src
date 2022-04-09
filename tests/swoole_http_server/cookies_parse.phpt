--TEST--
swoole_http_server: cookies parse
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use SwooleTest\ProcessManager;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        $client->setHeaders([
            'Cookie' => 'PHPSESSID=5359a08f4ddbf825f0e99a3393e5dc9e; HttpOnly; q=URVVma5UgEDm9RmQvBfXs7rCEG9hs9td9CXXmBRQ'
        ]);
        $client->get('/');
        $client->close();
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->on("Start", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($request, $response) use ($serv){
        var_dump($request->cookie);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(3) {
  ["PHPSESSID"]=>
  string(32) "5359a08f4ddbf825f0e99a3393e5dc9e"
  ["HttpOnly"]=>
  string(0) ""
  ["q"]=>
  string(40) "URVVma5UgEDm9RmQvBfXs7rCEG9hs9td9CXXmBRQ"
}
