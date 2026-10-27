--TEST--
swoole_event: dispatch rejects reentry from a deferred callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_async_set(['enable_coroutine' => false]);
Swoole\Coroutine::set(['log_level' => SWOOLE_LOG_ERROR]);
Swoole\Event::defer(function () {
    Swoole\Event::dispatch();
    echo "unreachable\n";
});
Swoole\Event::wait();
?>
--EXPECTF--
Fatal error: Swoole\Event::dispatch(): reactor wait failed, Error: %s[%d] in %s on line %d
