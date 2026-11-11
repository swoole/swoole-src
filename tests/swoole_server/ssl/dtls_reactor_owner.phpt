--TEST--
swoole_server/ssl: DTLS listener hands initialized sockets to their fd owner without relaying packet data
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $clients = [];
    $owners = [];
    for ($i = 0; $i < 16; $i++) {
        $client = new Swoole\Client(SWOOLE_SOCK_UDP | SWOOLE_SSL, SWOOLE_SOCK_SYNC);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        Assert::same($client->send("first:$i"), strlen("first:$i"));
        $reply = json_decode($client->recv(), true);
        Assert::same($reply['data'], "first:$i");
        Assert::same($reply['socket_fd'] % 2, $reply['reactor_id']);
        $owners[$reply['reactor_id']] = true;
        $clients[] = $client;
    }
    Assert::same(count($owners), 2);
    foreach ($clients as $i => $client) {
        Assert::same($client->send("next:$i"), strlen("next:$i"));
        $reply = json_decode($client->recv(), true);
        Assert::same($reply['data'], "next:$i");
        Assert::same($reply['socket_fd'] % 2, $reply['reactor_id']);
        $client->close();
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_UDP | SWOOLE_SSL);
    $server->set([
        'worker_num' => 2,
        'reactor_num' => 2,
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->on('workerStart', function (Swoole\Server $server, int $worker) use ($pm) {
        if ($worker === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Swoole\Server $server, int $fd, int $reactor, string $data) {
        $info = $server->getClientInfo($fd);
        Assert::same($info['socket_fd'] % 2, $reactor);
        Assert::true($server->send($fd, json_encode([
            'socket_fd' => $info['socket_fd'],
            'reactor_id' => $info['reactor_id'],
            'data' => $data,
        ])));
    });
    $server->on('packet', function () { Assert::true(false, 'DTLS uses onReceive'); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
