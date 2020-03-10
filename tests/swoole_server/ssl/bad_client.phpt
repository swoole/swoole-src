--TEST--
swoole_server/ssl: bad client
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

define('ERROR_FILE', __DIR__.'/ssl_error');

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    \Swoole\Coroutine\run(function () use ($pm) {
        $port = $pm->getFreePort();
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP); //同步阻塞
        if (!$client->connect('127.0.0.1', $port))
        {
            exit("connect failed\n");
        }
        $client->send("hello world");
        Assert::same($client->recv(), "");
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server("127.0.0.1", $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set(
        [
            'log_file' => ERROR_FILE,
            'open_tcp_nodelay' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        ]
    );
    $server->on('Receive', function ($serv, $fd, $tid, $data) {

    });
    $server->start();
};

$pm->childFirst();
$pm->run();
readfile(ERROR_FILE);
unlink(ERROR_FILE);
?>
--EXPECTF--
[%s]	WARNING	swSSL_accept: bad SSL client[127.0.0.1:%d], reason=%d, error_string=error:%s
[%s]	INFO	Server is shutdown now
