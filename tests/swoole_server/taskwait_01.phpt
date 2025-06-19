--TEST--
swoole_server: taskwait [blocking]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();

use Swoole\Client;
use Swoole\Process;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->parentFunc = function ($pid) use ($port) {
    $cli = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect('127.0.0.1', $port, 0.5) or exit('ERROR');

    $cli->send('array-01') or exit('ERROR');
    Assert::same($cli->recv(), 'OK');
    $cli->send('array-02') or exit('ERROR');
    Assert::same($cli->recv(), 'OK');
    $cli->send('string-01') or exit('ERROR');
    Assert::same($cli->recv(), 'OK');
    $cli->send('string-02') or exit('ERROR');
    Assert::same($cli->recv(), 'OK');
    $cli->send('timeout') or exit('ERROR');
    Assert::same($cli->recv(), 'OK');

    Process::kill($pid);
};

$pm->childFunc = function () use ($pm, $port) {
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $port, SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $serv->on('WorkerStart', function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        if ($data == 'array-01') {
            $res = $serv->taskwait(['type' => 'array', 'value' => $data]);
            if (!empty($res['name'])) {
                $serv->send($fd, 'OK');
            } else {
                $serv->send($fd, 'ERR');
            }
        } elseif ($data == 'array-02') {
            $res = $serv->taskwait(['type' => 'string', 'value' => $data]);
            if ($res == "hello world\n") {
                $serv->send($fd, 'OK');
            } else {
                $serv->send($fd, 'ERR');
            }
        } elseif ($data == 'string-01') {
            $res = $serv->taskwait('array');
            if (!empty($res['name'])) {
                $serv->send($fd, 'OK');
            } else {
                $serv->send($fd, 'ERR');
            }
        } elseif ($data == 'string-02') {
            $res = $serv->taskwait('string');
            if ($res == "hello world\n") {
                $serv->send($fd, 'OK');
            } else {
                $serv->send($fd, 'ERR');
            }
        } elseif ($data == 'timeout') {
            $res = $serv->taskwait('timeout', 0.2);
            if ($res === false) {
                $res = $serv->taskwait('string', 0.2);
                if ($res === "hello world\n") {
                    $serv->send($fd, 'OK');
                    return;
                }
            }
            $serv->send($fd, 'ERR');
        }
    });

    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data) {
        if (is_array($data)) {
            if ($data['type'] == 'array') {
                return ['name' => 'rango', 'year' => 1987];
            }
            return "hello world\n";
        }
        if ($data == 'array') {
            return ['name' => 'rango', 'year' => 1987];
        }
        if ($data == 'string') {
            return "hello world\n";
        }
        if ($data == 'timeout') {
            usleep(300000);
            return "task timeout\n";
        }
    });

    $serv->on('finish', function (Server $serv, $fd, $rid, $data) {});
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
