--TEST--
swoole_client_coro: sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function () {
    $port = get_one_free_port();

    go(function () use ($port) {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
        $socket->bind('127.0.0.1', $port);
        $peer = null;
        $ret = $socket->recvfrom($peer);
        Assert::assert($ret, 'hello');
        $ret = $socket->recvfrom($peer);
        Assert::assert($ret, 'hello');
        echo "DONE\n";
    });

    go(function () use ($port) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $cli->sendto('127.0.0.1', $port, "hello\n");
        $cli->sendto('localhost', $port, "hello\n");
        Assert::false($cli->sendto('error_domain', $port, "hello\n"));
        Assert::assert($cli->errCode, 704);
        Assert::assert($cli->errMsg, 'DNS Lookup resolve failed');
    });
});

?>
--EXPECT--
DONE
