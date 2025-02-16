--TEST--
swoole_server/single_thread: user setting
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_root();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$log_file = tempnam('/tmp', 'swoole_test_');
chmod($log_file, 0777);
file_put_contents($log_file, '');

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $log_file) {
    $url = 'http://127.0.0.1:' . $pm->getFreePort() . '/';
    posix_kill($pid, SIGUSR1);
    sleep(1);
    $output = file_get_contents($log_file);
    Assert::contains($output, 'reloading all workers');
    Assert::contains($output, 'failed to push WORKER_STOP message');
    $pm->kill();
    unlink($log_file);
};

$pm->childFunc = function () use ($pm, $log_file) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'single_thread' => true,
        'worker_num' => 1,
        'user' => 'www-data',
        'group' => 'www-data',
        'log_file' => $log_file,
    ]);
    $http->on('WorkerStart', function (Swoole\Http\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function ($request, $response) {
        $response->end('hello');
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
