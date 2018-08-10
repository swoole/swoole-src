--TEST--
swoole_server: sendfile with SSL
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', 9501))
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
    assert($bytes == $N);
    assert(md5_file(TEST_IMAGE) == md5($data));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        //'log_file' => '/dev/null',
        'kernel_socket_send_buffer_size' => 65536,
        'ssl_cert_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.crt',
        'ssl_key_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (swoole_server $serv, $fd) {
        $serv->sendfile($fd, TEST_IMAGE);
    });
    $serv->on('receive', function ($serv, $fd, $from_id, $data) {

    });
    $serv->start();
};


$pm->childFirst();
$pm->run();
?>
--EXPECT--
