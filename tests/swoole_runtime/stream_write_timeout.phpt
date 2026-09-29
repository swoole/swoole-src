--TEST--
swoole_runtime: stream write timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
default_socket_timeout=1
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    [$reader, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    stream_set_blocking($writer, false);

    while (@fwrite($writer, 'x') > 0) {
    }

    stream_set_blocking($writer, true);
    stream_set_timeout($writer, 0, 200000);
    $start = microtime(true);
    Assert::false(@fwrite($writer, 'x'));
    Assert::lessThan(microtime(true) - $start, 0.5);

    $metadata = stream_get_meta_data($writer);
    Assert::true($metadata['timed_out']);
    Assert::false($metadata['eof']);

    fclose($reader);
    fclose($writer);
});
?>
--EXPECT--
