--TEST--
swoole_client_coro: (length protocol) resume in onClose callback

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/api/swoole_server/TestServer.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->set([
            'open_length_check' => true,
            'package_max_length' => 1024 * 1024,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ]);
        $cli->connect('127.0.0.1', 9501);
        $data = str_repeat('A', 1025);
        $cli->send(pack('N', strlen($data)).$data);
        co::sleep(0.2);
        $retData = $cli->recv();
        assert(is_string($retData) and strlen($retData) > 0);
        $retData = $cli->recv();
        assert($retData == false);
        assert($cli->errCode === SWOOLE_ERROR_CLIENT_NO_CONNECTION || $cli->errCode === SOCKET_ECONNRESET);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        //'dispatch_mode'         => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $data = str_repeat('B', 1025);
        $serv->send($fd, pack('N', strlen($data)) . $data);
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
