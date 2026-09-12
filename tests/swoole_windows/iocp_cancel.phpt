--TEST--
swoole_windows: iocp cancellation
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Socket::class, false)) {
    die('skip coroutine socket not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());

    Assert::false($listener->accept(0.001));
    $timeoutError = $listener->errCode;
    Assert::integer($timeoutError);
    Assert::greaterThan($timeoutError, 0);

    for ($index = 1; $index < 8; $index++) {
        Assert::false($listener->accept(0.001));
        Assert::same($listener->errCode, $timeoutError);
    }

    $completion  = new Channel(1);
    $coroutineId = go(function () use ($listener, $completion) {
        Assert::false($listener->accept(-1));
        $completion->push($listener->errCode);
    });
    Assert::true(Coroutine::cancel($coroutineId));
    $cancellationError = $completion->pop(1);
    Assert::integer($cancellationError);
    Assert::greaterThan($cancellationError, 0);
    Assert::notSame($cancellationError, $timeoutError);

    $completion = new Channel(1);
    go(function () use ($listener, $completion) {
        Assert::false($listener->accept(-1));
        $completion->push($listener->errCode);
    });
    // The second call succeeds only while accept remains bound until Windows reports cancellation completion.
    Assert::true($listener->cancel());
    Assert::true($listener->cancel());
    $socketCancellationError = $completion->pop(1);
    Assert::integer($socketCancellationError);
    Assert::same($socketCancellationError, $cancellationError);

    $stats = Coroutine::stats();
    Assert::same($stats['iocp_blocking_task_num'], 0);
    Assert::same($stats['iocp_task_num'], 0);

    $send       = new Channel(1);
    $clientDone = new Channel(1);
    go(function () use ($listener, $send, $clientDone) {
        $client = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($client->connect('127.0.0.1', $listener->getsockname()['port']));
        Assert::true($send->pop(1));
        Assert::same($client->sendAll('payload'), 7);
        $client->close();
        $clientDone->push(true);
    });

    $connection = $listener->accept(-1);
    Assert::isInstanceOf($connection, Socket::class);
    Assert::false($connection->recv(7, 0.001));
    Assert::same($connection->errCode, $timeoutError);
    $send->push(true);
    Assert::same($connection->recvAll(7, 1), 'payload');
    $connection->close();
    Assert::true($clientDone->pop(1));
    $listener->close();

    echo "DONE\n";
});
?>
--EXPECT--
DONE
