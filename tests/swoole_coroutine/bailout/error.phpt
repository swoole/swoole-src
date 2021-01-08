--TEST--
swoole_coroutine/bailout: error
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;

register_shutdown_function(function () {
    echo 'shutdown' . PHP_EOL;
});
go(function () {
    throw new Error;
});
Event::wait();
?>
--EXPECTF--
Fatal error: Uncaught Error in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
shutdown
