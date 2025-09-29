--TEST--
swoole_coroutine/bailout: call co redis in shutdown function
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;

Co\run(function () {
    $redis = new \redis();
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    register_shutdown_function(function () use ($redis) {
        $redis->get('key');
    });
    usleep(10000);
});

Event::wait();
?>
--EXPECTF--
Fatal error: Uncaught Swoole\Error: API must be called in the coroutine in %s:%d
Stack trace:
#0 %s(%d): Redis->get('key')
#1 [internal function]: {closure%S}()
#2 {main}
  thrown in %s on line %d
