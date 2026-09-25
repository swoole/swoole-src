--TEST--
swoole_socket_coro: keep bound and peer unix dgram addresses separate
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$receiverPath = '/tmp/swoole-unix-dgram-receiver.sock';
$peerPath = '/tmp/swoole-unix-dgram-peer.sock';
$unboundReceiverPath = '/tmp/swoole-unix-dgram-unbound-receiver.sock';

@unlink($receiverPath);
@unlink($peerPath);
@unlink($unboundReceiverPath);

$boundPeer = null;
$boundPeerAddress = null;
$unboundPeerAddress = null;

go(function () use (
    $receiverPath,
    $peerPath,
    $unboundReceiverPath,
    &$boundPeer,
    &$boundPeerAddress,
    &$unboundPeerAddress
) {
    $receiver = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
    $boundPeer = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
    Assert::true($receiver->bind($receiverPath));
    Assert::true($boundPeer->bind($peerPath));
    Assert::same($boundPeer->sendto($receiverPath, 0, 'hello'), 5);
    Assert::same($receiver->recvfrom($boundPeerInfo), 'hello');
    $boundPeerAddress = $boundPeerInfo['address'];
    unset($receiver);

    $receiver = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
    $unboundPeer = new Swoole\Coroutine\Socket(AF_UNIX, SOCK_DGRAM, IPPROTO_IP);
    Assert::true($receiver->bind($unboundReceiverPath));
    Assert::same($unboundPeer->sendto($unboundReceiverPath, 0, 'hello'), 5);
    Assert::same($receiver->recvfrom($unboundPeerInfo), 'hello');
    $unboundPeerAddress = $unboundPeerInfo['address'];
});
Swoole\Event::wait();

$result = [
    'receiver_removed' => !file_exists($receiverPath),
    'peer_preserved' => file_exists($peerPath),
    'bound_peer_address' => $boundPeerAddress,
    'unbound_peer_address' => $unboundPeerAddress,
];

unset($boundPeer);
$result['peer_removed'] = !file_exists($peerPath);

var_dump($result);
echo "DONE\n";
?>
--CLEAN--
<?php
@unlink('/tmp/swoole-unix-dgram-receiver.sock');
@unlink('/tmp/swoole-unix-dgram-peer.sock');
@unlink('/tmp/swoole-unix-dgram-unbound-receiver.sock');
?>
--EXPECT--
array(5) {
  ["receiver_removed"]=>
  bool(true)
  ["peer_preserved"]=>
  bool(true)
  ["bound_peer_address"]=>
  string(32) "/tmp/swoole-unix-dgram-peer.sock"
  ["unbound_peer_address"]=>
  string(0) ""
  ["peer_removed"]=>
  bool(true)
}
DONE
