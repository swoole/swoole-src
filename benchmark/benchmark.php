#!/usr/bin/env php
<?php
$wait = new Swoole\Atomic(0);
$pid = pcntl_fork();
if ($pid === 0) {
    $http = new Swoole\Http\Server('127.0.0.1', 9501, SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null', 'log_level' => SWOOLE_LOG_INFO, 'worker_num' => swoole_cpu_num() * 2]);
    $http->on('workerStart', function () use ($wait) { $wait->set(1); });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('<h1>Hello Swoole!</h1>');
    });
    $http->start();
} else {
    $wait->wait();
    System('ab -c 128 -n 100000 -k http://127.0.0.1:9501/ 2>&1');
    Swoole\Process::kill($pid);
}
Swoole\Event::wait();
