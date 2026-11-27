--TEST--
swoole_thread/server: sendwait is rejected on both the owning worker and the master thread
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Thread;

Assert::setThrowException(true);
function assertSendwaitRejected(Swoole\Server $server, int $fd): void
{
    $warnings = 0;
    set_error_handler(function ($errno, $message) use (&$warnings) {
        Assert::contains($message, 'sendwait() is not supported in THREAD mode');
        $warnings++;
        return true;
    });
    try {
        Assert::false($server->sendwait($fd, 'unexpected'));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_OPERATION_NOT_SUPPORT);
    } finally {
        restore_error_handler();
    }
    Assert::same($warnings, 1);
}

$main = Thread::getInfo()['is_main_thread'];
$port = get_constant_port(__FILE__);
$server = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
    'worker_num' => 2,
    'log_file' => '/dev/null',
    'open_eof_check' => true,
    'package_eof' => "\n",
]);
$server->on('Start', function ($server) use ($port) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    try {
        Assert::true($client->connect('127.0.0.1', $port, 5));
        Assert::same($client->send("check\n"), 6);
        $reply = json_decode($client->recv(), true, flags: JSON_THROW_ON_ERROR);
        // The acceptor/master never owns the initialized connection's Socket.
        assertSendwaitRejected($server, $reply['fd']);
        Assert::same($client->send("verify\n"), 7);
        Assert::same($client->recv(), "owner-routed\n");
    } finally {
        $client->close();
        $server->shutdown();
    }
});
$server->on('Receive', function ($server, $fd, $reactorId, $data) {
    assertSendwaitRejected($server, $fd);
    Assert::true($server->send($fd, $data === "check\n" ? json_encode(['fd' => $fd]) . "\n" : "owner-routed\n"));
});
$server->start();
if ($main) {
    echo "DONE\n";
}
?>
--EXPECT--
DONE
