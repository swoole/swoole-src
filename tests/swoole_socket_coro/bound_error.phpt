--TEST--
swoole_socket_coro: bound error
--SKIPIF--
<?php
use Co\Socket;
use Swoole\Coroutine\Client;
use Swoole\Event;

require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();
go(function () use ($port) {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($server->bind('127.0.0.1', $port));
    Assert::assert($server->listen());
});
go(function () use ($port) {
    $cli = new Client(SWOOLE_SOCK_TCP);
    $ret = $cli->connect('127.0.0.1', $port);
    Assert::true($ret);
    go(function () use ($cli) {
        $cli->recv();
    });
    $cli->recv();
});
Event::wait();
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: Socket#%d has already been bound to another coroutine#%d, reading of the same socket in coroutine#%d at the same time is not allowed in %s:%d
Stack trace:
#0 %s(%d): Swoole\Coroutine\Client->recv()
#1 [internal function]: {%s}()
#2 {main}
  thrown in %s on line %d

 [Coroutine-3] Stack trace:
 -------------------------------------------------------------------
#0 %s(%d): Swoole\Coroutine\Client->recv()
#1 [internal function]: {%s}()
