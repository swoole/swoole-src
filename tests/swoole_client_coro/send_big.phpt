--TEST--
swoole_client_coro: send
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $r = $client->connect("127.0.0.1", $pm->getFreePort(), 0.5);
        Assert::assert($r);

        set_socket_coro_buffer_size($client->exportSocket(), 65536);

        $header = "POST /post.php HTTP/1.1\r\n";
        $header .= "Host: weibo.com\r\n";
        $header .= "Content-Type: application/x-www-form-urlencoded\r\n";
        $header .= "Accept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2\r\n";

        $_postData = ['data' => urlencode(RandStr::getBytes(128*1024)), 'message' => '', 'code' => 120];
        $_postBody = http_build_query($_postData)."_END\r\n\r\n";
        $header .=  "Content-Length: " . strlen($_postBody);

        Assert::assert($client->send($header));
        Assert::assert($client->send($_postBody));

        $data = $client->recv(5);
        Assert::same($data, "HTTP/1.1 200 OK\r\n\r\n");
        $client->close();
    });
    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'kernel_socket_recv_buffer_size' => 65536,
        'kernel_socket_send_buffer_size' => 65536,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('connect', function (swoole_server $serv, $fd)
    {

    });
    $serv->on('receive', function ($serv, $fd, $tid, $data)
    {
        usleep(5000);
        if (substr($data, -8, 8) == "_END\r\n\r\n") {
            $serv->send($fd, "HTTP/1.1 200 OK\r\n\r\n");
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
