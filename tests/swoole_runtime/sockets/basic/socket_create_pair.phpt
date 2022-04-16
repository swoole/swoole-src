--TEST--
swoole_runtime/sockets/basic: Test for socket_create_pair()
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $sockets = array();
    if (strtolower(substr(PHP_OS, 0, 3)) == 'win') {
        $domain = AF_INET;
    } else {
        $domain = AF_UNIX;
    }
    socket_create_pair($domain, SOCK_STREAM, 0, $sockets);
    Assert::count($sockets, 2);
    Assert::isInstanceOf($sockets[0], Swoole\Coroutine\Socket::class);
    Assert::isInstanceOf($sockets[1], Swoole\Coroutine\Socket::class);
});
?>
--EXPECT--
