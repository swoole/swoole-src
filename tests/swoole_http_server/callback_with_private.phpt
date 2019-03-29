--TEST--
swoole_http_server: http server with private callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->setWaitTimeout(0);
$pm->parentFunc = function () { };
$pm->childFunc = function () use ($pm) {
    class TestCo
    {
        private function foo(swoole_http_request $request, swoole_http_response $response)
        {
            co::sleep(0.001);
            $cid = go(function () use ($response) {
                co::yield();
                $response->end('Hello Swoole!');
            });
            co::resume($cid);
            echo @$this->test;
        }
    }

    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $http->on('request', [new TestCo, 'foo']);
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Server::on() must be callable, array given in %s/tests/swoole_http_server/callback_with_private.php:%d
Stack trace:
#0 %s/tests/swoole_http_server/callback_with_private.php(%d): Swoole\Server->on('request', Array)
#1 %s/tests/include/functions.php(%d): {closure}()
#2 %s/tests/include/functions.php(%d): ProcessManager->runChildFunc()
#3 [internal function]: ProcessManager->{closure}(Object(Swoole\Process))
#4 %s/tests/include/functions.php(%d): Swoole\Process->start()
#5 %s/tests/swoole_http_server/callback_with_private.php(%d): ProcessManager->run()
#6 {main}
  thrown in %s/tests/swoole_http_server/callback_with_private.php on line %d
