--TEST--
swoole_coroutine: eval
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::same(Co::stats()['coroutine_num'], 0);

go(function () {
    echo "start 1\n";
    eval('Co::sleep(0.5);');
    echo "end 1\n";
});
go(function () {
    eval(' echo "start 2\n" ;');
    Co::sleep(0.5);
    echo "end 2\n";
});
echo "main end\n";
?>
--EXPECT--
start 1
start 2
main end
end 1
end 2
