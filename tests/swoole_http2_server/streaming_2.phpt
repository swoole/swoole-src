--TEST--
swoole_http2_server: streaming 2
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_nghttp();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\ChildProcess;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $proc = ChildProcess::exec("nghttp http://127.0.0.1:{$pm->getFreePort()}/");
    $out = '';
    while($line = $proc->read()) {
        $out .= $line;
        if (str_contains($line, 'hello world, #0')) {
            break;
        }
    }
    echo $out;
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $http->on('WorkerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $n = 5;
        while ($n--) {
            $response->write("hello world, #$n\n");
            Co\System::sleep(0.1);
        }
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
hello world, #4
hello world, #3
hello world, #2
hello world, #1
hello world, #0
