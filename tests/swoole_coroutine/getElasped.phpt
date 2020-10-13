--TEST--
swoole_coroutine: getElapsed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    var_dump(Co::getElapsed(1000));
    var_dump(Co::getElapsed(-1));
    co::sleep(.001);
    var_dump(Co::getElapsed() === Co::getElapsed(Co::getCid()));
});

?>
--EXPECT--
int(-1)
int(-1)
bool(true)
