--TEST--
swoole_coroutine_scheduler: invalid exit_condition preserves old callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$count = 0;
Swoole\Coroutine::set([
    'exit_condition' => function () use (&$count) {
        $count++;
        return true;
    },
]);

Swoole\Coroutine::set(['exit_condition' => 'not_found_function']);
Swoole\Timer::after(1, function () {});
Swoole\Event::wait();

Assert::eq($count, 1);
echo "DONE\n";
?>
--EXPECTF--
Warning: Swoole\Coroutine::set(): function 'not_found_function' is not callable in %s on line %d
DONE
