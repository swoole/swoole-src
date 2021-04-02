--TEST--
swoole_client_sync: sendto
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('fixme');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $cli = new Client(SWOOLE_SOCK_UDP);

    Assert::true($cli->sendto('127.0.0.1', $pm->getFreePort(), "packet-1"));
    Assert::true($cli->sendto('localhost', $pm->getFreePort(), "packet-2"));
    Assert::false($cli->sendto('error_domain', $pm->getFreePort(), "hello"));
    Assert::assert($cli->errCode, SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
    Assert::true($cli->sendto('localhost', $pm->getFreePort(), "packet-3"));
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
        $socket->bind('127.0.0.1', $pm->getFreePort());
        $pm->wakeup();
        $peer = null;
        $ret = $socket->recvfrom($peer);
        Assert::eq($ret, 'packet-1');
        $ret = $socket->recvfrom($peer);
        Assert::eq($ret, 'packet-2');
        $ret = $socket->recvfrom($peer);
        Assert::eq($ret, 'packet-3');
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Client::sendto(): sendto to server[error_domain:%d] failed. Error: DNS Lookup resolve failed[704] in %ssendto.php on line %d
DONE
