#!/usr/bin/env php
<?php
$process = new Swoole\Process(function (Swoole\Process $process) {
    $http = new Swoole\Http\Server('127.0.0.1', 9501, SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null', 'log_level' => SWOOLE_LOG_INFO, 'worker_num' => swoole_cpu_num() * 2]);
    $http->on('workerStart', function () use ($process) { $process->write('1'); });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('<h1>Hello Swoole!</h1>');
    });
    $http->start();
});
$process->start();
$process->read(1);
System('ab -c 128 -n 100000 -k http://127.0.0.1:9501/ 2>&1');
Swoole\Process::kill($process->pid);
