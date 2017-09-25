--TEST--
swoole_server: pid_file
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
const PID_FILE = __DIR__.'/test.pid';
$port = 9508;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    assert(is_file(PID_FILE));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server("127.0.0.1", $port);
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

