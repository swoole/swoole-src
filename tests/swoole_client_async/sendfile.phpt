--TEST--
swoole_client: async sendfile

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $client->on("connect", function (Swoole\Client $cli)
    {
        $filename = __DIR__ . "/test.jpg";
        $cli->send(pack('N', filesize($filename)));
        $ret = $cli->sendfile($filename);
        assert($ret);
    });
    $client->on("receive", function (Swoole\Client $cli, $data)
    {
        $filename = __DIR__ . "/test.jpg";
        $cli->send(pack('N', 8) . 'shutdown');
        $cli->close();
        assert($data === md5_file($filename));
    });
    $client->on("error", function($cli){
        echo "Connect failed\n";
    });
    $client->on("close", function($cli){

    });
    $client->connect(TCP_SERVER_HOST, TCP_SERVER_PORT, 0.5);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, TCP_SERVER_PORT, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'dispatch_mode' => 1,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'package_max_length' => 2000000,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data)
    {
        if (substr($data, 4, 8) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        $serv->send($fd, md5(substr($data, 4)));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
