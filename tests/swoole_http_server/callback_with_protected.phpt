--TEST--
swoole_http_server: http server with protected callback
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
        protected function foo(swoole_http_request $request, swoole_http_response $response)
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
$pm->run(true);
//Fatal Error
$pm->expectExitCode(255);
$output = $pm->getChildOutput();
Assert::contains($output, 'Swoole\Server::on() must be callable');
?>
--EXPECT--
