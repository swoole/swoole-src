--TEST--
swoole_http_server: bug 2751
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        echo httpGetStatusCode("http://127.0.0.1:{$pm->getFreePort()}/test™") . PHP_EOL;
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on(Constant::EVENT_WORKER_START, function () use ($pm) {
        $pm->wakeup();
    });
    $http->on(Constant::EVENT_REQUEST, function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        var_dump('never here');
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
400
