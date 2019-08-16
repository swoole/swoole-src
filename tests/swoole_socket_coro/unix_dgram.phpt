--TEST--
swoole_socket_coro: unix dgram
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    @unlink('/tmp/test-server.sock');
    $server = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
    $server->bind('/tmp/test-server.sock');
    go(function () use ($server) {
        while ($data = $server->recvfrom($peer)) {
            Assert::same($data, 'hello');
            $server->sendto($peer['address'], 0, 'world');
        }
        var_dump($peer);
    });
    go(function () use ($server) {
        @unlink('/tmp/test-client.sock');
        $client = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
        $client->bind('/tmp/test-client.sock');
        $peer = [];
        for ($n = MAX_REQUESTS; $n--;) {
            $client->sendto('/tmp/test-server.sock', 0, 'hello');
            $data = $client->recvfrom($peer);
            Assert::notEmpty($data);
            if (empty($data)) {
                break;
            }
            Assert::same($data, 'world');
        }
        var_dump($peer);
        $client->close();
        $server->close();
    });
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
array(2) {
  ["address"]=>
  string(21) "/tmp/test-server.sock"
  ["port"]=>
  int(0)
}
array(2) {
  ["address"]=>
  string(21) "/tmp/test-client.sock"
  ["port"]=>
  int(0)
}
DONE
