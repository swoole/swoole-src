--TEST--
swoole_runtime/sockets: socket_export_stream uses Coroutine Socket export with independent lifetime
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_SOCKETS);
Swoole\Coroutine\run(function () {
    $domain = PHP_OS_FAMILY === 'Windows' ? AF_INET : AF_UNIX;
    socket_create_pair($domain, SOCK_STREAM, 0, $pair);
    $stream = socket_export_stream($pair[0]);
    if (!is_resource($stream) || !($pair[0] instanceof Swoole\Coroutine\Socket)) {
        throw new RuntimeException('Wrong export implementation');
    }
    stream_set_timeout($stream, 1);
    socket_set_option($pair[1], SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
    socket_close($pair[0]);
    if (fwrite($stream, 'hello') !== 5 || socket_read($pair[1], 5) !== 'hello') {
        throw new RuntimeException('Closing the source invalidated the exported stream');
    }
    fclose($stream);
    if (socket_read($pair[1], 1) !== '') {
        throw new RuntimeException('The duplicated descriptor leaked');
    }
    socket_close($pair[1]);
});
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
