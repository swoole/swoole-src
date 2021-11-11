--TEST--
swoole_http_server: http server with protected callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\ProcessManager;

$pm = ProcessManager::exec(function ($pm) {
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
});
//Fatal Error
$pm->expectExitCode(255);
$output = $pm->getChildOutput();
if (PHP_VERSION_ID < 80000) {
    Assert::contains($output, 'Swoole\Server::on() must be callable');
} else {
    Assert::contains($output, 'Swoole\Server::on(): function \'TestCo::foo\' is not callable');
}
?>
--EXPECT--
