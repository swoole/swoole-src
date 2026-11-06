--TEST--
swoole_thread/server: length callbacks belong to each worker VM and inherited ports retain their callback
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Thread;

Assert::setThrowException(true);
$ports = array_map(fn ($i) => get_constant_port(__FILE__ . $i), range(0, 2));
$server = new Swoole\Server('127.0.0.1', $ports[0], SWOOLE_THREAD);
$createdIn = Thread::getId();
$length = function (string $data) use ($createdIn): int {
    Assert::same(Thread::getId(), $createdIn);
    return strlen($data) < 4 ? 0 : unpack('N', $data)[1];
};
$result = $server->set([
    'worker_num' => 2,
    'log_file' => '/dev/null',
    'max_wait_time' => 1,
    'open_length_check' => true,
    'package_length_func' => $length,
]);
Assert::same($result, Thread::getInfo()['is_main_thread']);
$server->listen('127.0.0.1', $ports[1], SWOOLE_SOCK_TCP);
$explicit = $server->listen('127.0.0.1', $ports[2], SWOOLE_SOCK_TCP);
$explicitLength = function (string $data) use ($createdIn): int {
    Assert::same(Thread::getId(), $createdIn);
    return strlen($data) < 4 ? 0 : unpack('N', $data)[1] + 4;
};
Assert::same($explicit->set([
    'open_length_check' => true,
    'package_length_func' => $explicitLength,
]), Thread::getInfo()['is_main_thread']);
$server->on('receive', function ($server, $fd, $reactorId, $data) {
    Assert::same(substr($data, 4), 'hello');
    $server->send($fd, (string) $server->worker_id);
});
$server->on('workerStart', function ($server, $workerId) use ($ports) {
    // A worker set() must not change shared native settings or its settings snapshot.
    $settings = $server->setting;
    Assert::false($server->set(['worker_num' => 99, 'package_length_type' => '?']));
    Assert::same($server->setting, $settings);
    if ($workerId !== 0) {
        return;
    }
    Coroutine::create(function () use ($server, $ports) {
        try {
            foreach ($ports as $i => $port) {
                $seen = [];
                $clients = [];
                $descriptors = [];
                try {
                    for ($attempt = 0; $attempt < 32 && count($seen) < 2; $attempt++) {
                        // Client and accepted sockets share an FD table in thread mode. Keep them
                        // open and add one FD per attempt so fd % worker_num reaches both workers.
                        $descriptors[] = fopen(__FILE__, 'rb');
                        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                        $clients[] = $client;
                        Assert::true($client->connect('127.0.0.1', $port, 2));
                        $packet = pack('N', $i === 2 ? 5 : 9) . 'hello';
                        Assert::same($client->send(substr($packet, 0, 2)), 2);
                        Coroutine::sleep(0.001);
                        Assert::same($client->send(substr($packet, 2)), 7);
                        $reply = $client->recv(2);
                        Assert::true($reply === '0' || $reply === '1');
                        $seen[$reply] = true;
                    }
                } finally {
                    foreach ($clients as $client) {
                        $client->close();
                    }
                    foreach ($descriptors as $descriptor) {
                        fclose($descriptor);
                    }
                }
                Assert::count($seen, 2);
            }
        } finally {
            $server->shutdown();
        }
    });
});
$server->start();
if (Thread::getInfo()['is_main_thread']) {
    echo "DONE\n";
}
?>
--EXPECT--
DONE
