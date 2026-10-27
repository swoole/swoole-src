--TEST--
swoole_event: dispatch rejects reentry from an I/O callback
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_async_set(['enable_coroutine' => false]);
Swoole\Coroutine::set(['log_level' => SWOOLE_LOG_ERROR]);
[$reader, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
Swoole\Event::add($reader, function ($socket) {
    fread($socket, 1);
    Swoole\Event::dispatch();
    echo "unreachable\n";
});
fwrite($writer, 'x');
Swoole\Event::wait();
?>
--EXPECTF--
Fatal error: Swoole\Event::dispatch(): reactor wait failed, Error: %s[%d] in %s on line %d
