--TEST--
swoole_server: check callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process;

function test_create_server($class, $callback)
{
    $proc = new Process(function () use ($class) {
        $server = new $class('127.0.0.1');
        $server->start();
    }, true, SOCK_STREAM, false);
    $proc->start();
    $result = Process::wait();
    Assert::contains($proc->read(), 'require on'.ucfirst($callback).' callback');
    Assert::eq($result['code'], 255);
}

test_create_server(Swoole\Server::class, Constant::EVENT_RECEIVE);
test_create_server(Swoole\Http\Server::class, Constant::EVENT_REQUEST);
test_create_server(Swoole\WebSocket\Server::class, Constant::EVENT_MESSAGE);

$proc = new Process(function ()  {
    $server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $server->start();
}, true, SOCK_STREAM, false);
$proc->start();
$result = Process::wait();
Assert::contains($proc->read(), 'require onPacket callback');
Assert::eq($result['code'], 255);
?>
--EXPECT--
