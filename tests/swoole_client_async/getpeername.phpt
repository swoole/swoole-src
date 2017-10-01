--TEST--
swoole_client: getsockpeername

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
    $cli = new \swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (\swoole_client $cli) {
        assert($cli->isConnected() === true);
        $cli->send("test");
    });

    $cli->on("receive", function(\swoole_client $cli, $data){
        $i = $cli->getpeername();
        assert($i !== false);
        $cli->send('shutdown');
        $cli->close();
    });

    $cli->on("close", function(\swoole_client $cli) {
        echo "SUCCESS\n";
    });

    $r = $cli->connect(UDP_SERVER_HOST, UDP_SERVER_PORT, 1);
    assert($r);
    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(UDP_SERVER_HOST, UDP_SERVER_PORT, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Packet", function (\swoole_server $serv, $data, $clientInfo)
    {
        if (trim($data) == 'shutdown')
        {
            $serv->shutdown();
            return;
        }
        $serv->sendto($clientInfo['address'], $clientInfo['port'], $data);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>

--EXPECT--
SUCCESS
