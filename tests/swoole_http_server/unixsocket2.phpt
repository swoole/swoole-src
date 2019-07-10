--TEST--
swoole_http_server: http unix socket [2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Response;

const SOCKET = __DIR__ . '/server.sock';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_UNIX_SOCKET_PATH, SOCKET);
    curl_setopt($ch, CURLOPT_URL, "http://localhost/?a=hello&b=12345&test=world");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $output = curl_exec($ch);
    var_dump($output);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(SOCKET, 0, SWOOLE_PROCESS, SWOOLE_SOCK_UNIX_STREAM);
    $serv->set([
        'log_file' => '/dev/null',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, Response $resp) {
        $resp->end(json_encode($req->get, true));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
string(40) "{"a":"hello","b":"12345","test":"world"}"
