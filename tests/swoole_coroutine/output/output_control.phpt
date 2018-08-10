--TEST--
swoole_coroutine: ob_* in coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../../include/bootstrap.php';
ob_start();
echo 'main';
// #co1
go(function () {
    ob_start();
    echo "foo\n";
    $ob_1 = (ob_get_status(true));
    // yield and it will switch to #co2
    co::sleep(0.1);
    // resume to ob_1
    assert($ob_1 === (ob_get_status(true)));
    ob_start(); // ob_2
    echo "bar\n";
    assert(ob_get_status()['level'] === 1);
    ob_start(); // ob_3
    // yield and it will switch to #co3
    co::sleep(0.2);
    // resume to ob_3
    assert(ob_get_status()['level'] === 2);
    echo "baz\n";
    assert(ob_get_clean() === "baz\n"); // clean ob_3
    echo ob_get_clean(); // ob_1, ob_2, expect foo\n bar\n;
});

// #co2
go(function () {
    assert(ob_get_status(true) === []); //empty
    assert(!ob_get_contents());
    co::sleep(0.001);
    assert(!ob_get_clean());
});

// #co3
go(function () {
    co::sleep(0.2);
    assert(ob_get_status(true) === []); //empty
});
assert(ob_get_clean() === 'main');
?>
--EXPECT--
foo
bar