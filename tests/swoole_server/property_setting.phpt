--TEST--
swoole_server: property of setting
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

\Swoole\Async::set(['log_level' => SWOOLE_LOG_ERROR]);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', 9501, 5, 0))
    {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }
    assert($client->send('get'));
    $res = $client->recv();
    $json = json_decode($res, true);
    assert($json);
    assert(is_array($json));
    assert(isset($json['worker_num']));
    assert($json['worker_num'] == swoole_cpu_num());
    usleep(100000);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server("127.0.0.1", 9501);
    $serv->set(array(
        'log_file' => '/dev/null',
        'log_level' => SWOOLE_LOG_ERROR,
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $serv->send($fd, json_encode($serv->setting));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
