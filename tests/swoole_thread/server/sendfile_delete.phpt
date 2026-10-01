--TEST--
swoole_thread/server: sendfile delete_file removes the file after transfer
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

$port = get_constant_port(__FILE__);
$path    = sys_get_temp_dir() . '/swoole_thread_sendfile_delete_' . $port . '.bin';
$content = str_repeat('swoole thread sendfile delete payload ', 4096);

$serv = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num'     => 1,
    'log_level'      => SWOOLE_LOG_ERROR,
    'init_arguments' => function () use ($path, $content) {
        global $atomic;
        // Worker threads re-run this script, so create the file once here, before they start.
        file_put_contents($path, $content);
        $atomic = new Thread\Atomic(0);
        return [$atomic];
    },
]);
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) {
    [$atomic] = Thread::getArguments();
    $atomic->add();
});
$serv->on('Request', function ($request, $response) use ($path) {
    $response->sendfile($path, 0, 0, true);
});
$serv->on('shutdown', function () {
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv, $path, $content, $port) {
    [$atomic] = Thread::getArguments();
    while ($atomic->get() < 1) {
        usleep(10 * 1000);
    }
    $body = file_get_contents('http://127.0.0.1:' . $port . '/download');
    Assert::same(md5($body), md5($content));
    for ($i = 0; $i < 200; $i++) {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            break;
        }
        usleep(25 * 1000);
    }
    clearstatcache(true, $path);
    Assert::false(is_file($path));
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
@unlink($path);
?>
--EXPECT--
done
shutdown
