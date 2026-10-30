--TEST--
swoole_client_sync: shutdown connections are closed instead of pooled
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// Leave connections unaccepted so a peer FIN cannot mask the client's shutdown state.
$context = stream_context_create(['socket' => ['backlog' => 32]]);
$server = stream_socket_server('tcp://' . TCP_SERVER_HOST . ':0', $errno, $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
Assert::notSame($server, false, "$errstr ($errno)");
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$type = SWOOLE_SOCK_TCP | SWOOLE_KEEP | SWOOLE_SYNC;

// An ordinary connection still returns to the pool.
$client = new Swoole\Client($type);
Assert::true($client->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($client->close());
$reused = new Swoole\Client($type);
Assert::true($reused->connect(TCP_SERVER_HOST, $port, 0.5));
Assert::true($reused->reuse);
Assert::true($reused->close(true));

foreach ([Swoole\Client::SHUT_RD, Swoole\Client::SHUT_WR, Swoole\Client::SHUT_RDWR] as $how) {
    $client = new Swoole\Client($type);
    Assert::true($client->connect(TCP_SERVER_HOST, $port, 0.5));
    Assert::true($client->shutdown($how));
    $fd = $client->sock;
    Assert::true($client->close());

    // Check immediate descriptor closure, including SHUT_RD which a later liveness check could reject.
    $probe = @fopen('php://fd/' . $fd, 'r');
    if (is_resource($probe)) {
        fclose($probe);
    }
    Assert::false($probe, 'shutdown descriptor must be closed immediately');

    $replacement = new Swoole\Client($type);
    Assert::true($replacement->connect(TCP_SERVER_HOST, $port, 0.5));
    Assert::false($replacement->reuse);
    Assert::true($replacement->close(true));
}

fclose($server);
?>
--EXPECT--
