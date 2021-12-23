--TEST--
swoole_runtime/sockets: import
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $s = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

    $s0 = reset($s);
    $s1 = next($s);

    $sock = socket_import_stream($s0);
    Assert::notEmpty($sock);
    socket_write($sock, "test message");
    socket_close($sock);

    var_dump(stream_get_contents($s1));
});
echo "Done\n";
?>
--EXPECT--
string(12) "test message"
Done
