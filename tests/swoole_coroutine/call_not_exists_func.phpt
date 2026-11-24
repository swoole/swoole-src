--TEST--
swoole_coroutine: call_not_exists_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; skip_if_win(); ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = ProcessManager::exec(function () {
    $http = new Swoole\Http\Server('127.0.0.1', 0, SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () {
        none();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        co::sleep(0.001);
        throw new Exception('whoops');
    });
    $http->start();
});
echo $pm->getChildOutput();
Assert::greaterThan($pm->getChildExitStatus(), 0);
?>
--EXPECTF--
Fatal error: Uncaught Error: Call to undefined function none() in %s:%d
Stack trace:
%A
  thrown in %s on line %d
[%s]	ERROR	php_swoole_server_rshutdown() (ERRNO %d): Fatal error: Uncaught Error: Call to undefined function none() in %s:%d
Stack trace:
%A
  thrown in %s on line %d
