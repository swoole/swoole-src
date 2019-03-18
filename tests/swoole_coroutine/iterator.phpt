--TEST--
swoole_coroutine: iterator
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $i = Co::list();
    var_dump($i->current());
    $i->next();
    var_dump($i->current());
    $i->rewind();
    go(function () use ($i) {
        Co::sleep(0.1);
        var_dump($i->current());
        $i->next();
        var_dump($i->current());
    });
});
?>
--EXPECT--
int(1)
NULL
int(2)
NULL
