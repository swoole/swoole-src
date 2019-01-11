--TEST--
swoole_server: test dispatch_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $port) {
    $client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $port))
    {
        exit("connect failed\n");
    }
    $data = strval(time());
    $client->send($data);
    assert($data === $client->recv());
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $port) {
    $server = new Swoole\Server('127.0.0.1', $port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
    $server->set([
        'worker_num' => rand(4, 8),
        'log_file'   => '/dev/null',
        'dispatch_func' => function($server, $fd, $type, $data) {
            return $fd % $server->setting['worker_num'];
        }
    ]);
    $server->on('packet', function($server, $data, $client) {
        $fd = unpack('L', pack('N', ip2long($client['address'])))[1];
        assert($fd % $server->setting['worker_num'] === $server->worker_id);
        $server->sendto($client['address'], $client['port'], $data);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
