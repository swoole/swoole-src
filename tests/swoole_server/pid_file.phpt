--TEST--
swoole_server: pid_file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const PID_FILE = __DIR__.'/test.pid';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    assert(is_file(PID_FILE));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'pid_file' => PID_FILE,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
clearstatcache();
assert(!is_file(PID_FILE));
?>
--EXPECT--
