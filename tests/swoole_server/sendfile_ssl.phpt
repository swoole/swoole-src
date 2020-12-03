--TEST--
swoole_server: sendfile with SSL
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', $pm->getFreePort()))
    {
        exit("connect failed\n");
    }

    $socket = $client->getSocket();
    socket_set_option($socket, SOL_SOCKET, SO_SNDBUF, 65536);
    socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 65536);

    $N = filesize(TEST_IMAGE);
    $bytes = 0;
    $data = '';
    while ($bytes < $N)
    {
        $n = rand(8192, 65536);
        $r = $client->recv($n);
        if (!$r)
        {
            break;
        }
        usleep(10000);
        $bytes += strlen($r);
        $data .= $r;
    }
    Assert::same($bytes, $N);
    Assert::same(md5_file(TEST_IMAGE), md5($data));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        //'log_file' => '/dev/null',
        'kernel_socket_send_buffer_size' => 65536,
        'ssl_cert_file' => SSL_FILE_DIR.'/server.crt',
        'ssl_key_file' => SSL_FILE_DIR.'/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (swoole_server $serv, $fd) {
        Assert::true($serv->sendfile($fd, TEST_IMAGE));
    });
    $serv->on('receive', function ($serv, $fd, $reactor_id, $data) {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
