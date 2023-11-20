--TEST--
swoole_coroutine/bailout: call co redis in shutdown function
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;

Co\run(function (){
   $redis = new \redis();
   $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    register_shutdown_function(function () use ($redis) {
        try {
            $redis->get('key');
        }catch (Exception $e) {
            var_dump($e);
        }
    });
    usleep(10000);
});

Event::wait();
?>
--EXPECTF--
