--TEST--
swoole_server: force reload in process mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (swoole_cpu_num() === 1) {
    skip('not support on machine with single cpu');
}
?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$atomic = new Swoole\Atomic();
const WORKER_NUM = 4;

$pm->parentFunc = function ($pid) use ($pm) {
    $n = WORKER_NUM;
    $clients = [];
    while ($n--) {
        $client = new swoole_client(SWOOLE_SOCK_TCP);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("hello world");
        $clients[] = $client;
    }
    //reload
    echo "[-1] start to reload\n";
    Swoole\Process::kill($pid, SIGUSR1);
    sleep(4);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => WORKER_NUM,
        "max_wait_time" => 1,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $server, $worker_id) use ($pm, $atomic) {
        echo "$worker_id [" . $server->worker_pid . "] start\n";
        $atomic->add(1);
        if ($atomic->get() == 4) {
            $pm->wakeup();
        }
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        sleep(10);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%d [%d] start
%d [%d] start
%d [%d] start
%d [%d] start
%s start to reload
[%s]	INFO	Server is reloading all workers now
[%s]	WARNING	swManager_kill_timeout_process (ERRNO 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill
[%s]	WARNING	swManager_kill_timeout_process (ERRNO 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill
[%s]	WARNING	swManager_kill_timeout_process (ERRNO 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill
[%s]	WARNING	swManager_kill_timeout_process (ERRNO 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
%d [%d] start
%d [%d] start
%d [%d] start
%d [%d] start
[%s]	INFO	Server is shutdown now
