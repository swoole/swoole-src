--TEST--
swoole_runtime/sockets/basic: Test if socket_create_listen() returns false, when it cannot bind to the port.
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}
$filename = __FILE__ . '.root_check.tmp';
$fp = fopen($filename, 'w');
fclose($fp);
if (fileowner($filename) == 0) {
    unlink($filename);
    die('SKIP Test cannot be run as root.');
}
unlink($filename);
if (@socket_create_listen(80)) {
    die('SKIP Test cannot be run in environment that will allow binding to port 80 (azure)');
}?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $sock = socket_create_listen(80);
    Assert::false($sock);
    Assert::eq(socket_last_error(), SOCKET_EACCES);
});
?>
--EXPECT--
