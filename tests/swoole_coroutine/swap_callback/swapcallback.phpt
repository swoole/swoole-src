--TEST--
swoole_coroutine: coro swap callback
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
co::onSwapIn(function($cid) {
    echo "hook:onSwapIn $cid\n";
});
co::onSwapOut(function($cid) {
    echo "hook:onSwapOut $cid\n";
});
go(function () {    
    echo "start coro ".co::getuid()."\n";
    co::sleep(0.5);
    go(function () {
        echo "start coro ".co::getuid()."\n";
        co::sleep(0.5);
        go(function () {
            echo "start coro ".co::getuid()."\n";
            co::sleep(0.5);
            echo "end coro ".co::getuid()."\n";
        });
        echo "end coro ".co::getuid()."\n";
    });
    echo "end coro ".co::getuid()."\n";
});

go(function () {
    echo "start coro ".co::getuid()."\n";
    co::sleep(0.5);
    echo "end coro ".co::getuid()."\n";
});
echo "main end\n";
    


?>
--EXPECT--
hook:onSwapIn 1
start coro 1
hook:onSwapOut 1
hook:onSwapIn 2
start coro 2
hook:onSwapOut 2
main end
hook:onSwapIn 1
hook:onSwapIn 3
start coro 3
hook:onSwapOut 3
end coro 1
hook:onSwapOut 1
hook:onSwapIn 2
end coro 2
hook:onSwapOut 2
hook:onSwapIn 3
hook:onSwapIn 4
start coro 4
hook:onSwapOut 4
end coro 3
hook:onSwapOut 3
hook:onSwapIn 4
end coro 4
hook:onSwapOut 4
