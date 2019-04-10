--TEST--
swoole_server: unix socket dgram server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

parent_child(function ($pid)
{
    usleep(100000);
    $client = new \swoole_client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC);
    $r = $client->connect(UNIXSOCK_PATH, 0, -1);
    if ($r === false)
    {
        echo "ERROR";
        exit;
    }
    $client->send("SUCCESS");
    echo $client->recv();
    $client->close();
}, function ()
{
    $serv = new \swoole_server(UNIXSOCK_PATH, 0, SWOOLE_PROCESS, SWOOLE_UNIX_DGRAM);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null', 'daemonize' => true]);
    $serv->on("WorkerStart", function (\swoole_server $serv)
    {
        swoole_timer_after(1000, function () use ($serv)
        {
            @unlink(UNIXSOCK_PATH);
            $serv->shutdown();
        });
    });
    $serv->on("packet", function (\swoole_server $serv, $data, $addr)
    {
        $serv->send($addr['address'], 'SUCCESS');
    });
    $serv->start();
});
?>
--EXPECT--
SUCCESS
