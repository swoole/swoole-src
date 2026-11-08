--TEST--
swoole_server/mqtt: fragmented Remaining Length and consecutive packets
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$packets = [
    "\xc0\x00",
    "\x30\x80\x01" . str_repeat('x', 128),
    "\x30\x80\x80\x01" . str_repeat('y', 16384),
    "\xc0\x00",
];
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $packets) {
    Co\run(function () use ($pm, $packets) {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
        foreach ($packets as $index => $packet) {
            $headerLength = [2, 3, 4, 2][$index];
            for ($byte = 0; $byte < $headerLength; $byte++) {
                Assert::same($socket->sendAll($packet[$byte]), 1);
                Co::sleep(0.001);
            }
            if (strlen($packet) > $headerLength) {
                Assert::same($socket->sendAll(substr($packet, $headerLength)), strlen($packet) - $headerLength);
            }
            Assert::same($socket->recvAll(4), pack('N', strlen($packet)));
        }
        // Also deliver several complete frames in a single write.
        Assert::same($socket->sendAll(implode('', $packets)), array_sum(array_map('strlen', $packets)));
        foreach ($packets as $packet) {
            Assert::same($socket->recvAll(4), pack('N', strlen($packet)));
        }
        $socket->close();
        echo "DONE\n";
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $packets) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'open_mqtt_protocol' => true]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $received = 0;
    $server->on('Receive', function ($server, $fd, $reactorId, $data) use ($packets, &$received) {
        Assert::same($data, $packets[$received++ % count($packets)]);
        $server->send($fd, pack('N', strlen($data)));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
