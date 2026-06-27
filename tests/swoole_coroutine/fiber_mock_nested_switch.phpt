--TEST--
swoole_coroutine: fiber mock nested switch
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
ini_set('swoole.enable_fiber_mock', 'On');
\Swoole\Coroutine\run(function () {
    $chan = new \Swoole\Coroutine\Channel(1);

    \Swoole\Coroutine\go(function () use ($chan) {
        echo "outer-start\n";

        \Swoole\Coroutine\go(function () use ($chan) {
            echo "inner-start\n";
            $chan->push("inner-ready");
            echo "inner-end\n";
        });

        echo $chan->pop() . "\n";
        echo "outer-end\n";
    });
});
?>
--EXPECT--
outer-start
inner-start
inner-end
inner-ready
outer-end
