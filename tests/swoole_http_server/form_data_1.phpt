--TEST--
swoole_http_server: form data 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

const OFFSET = 250;

$pm = new ProcessManager;
$pm->initFreePorts();

$pm->parentFunc = function ($pid) use ($pm) {
    form_data_test_1($pm);
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set(['log_file' => '/dev/null']);
    $http->on('WorkerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function (Request $request, Response $response) use ($http) {
        $response->end(json_encode($request->post));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
