--TEST--
swoole_coroutine: autoload not found
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

spl_autoload_register(function ($class) {
    if ($class == 'SwooleTestClassA2') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/A2.php';
    }
});

Co\run( function() {
    try {
        var_dump(new SwooleTestClassA2());
    } catch (\Throwable $e) {
        Assert::contains($e->getMessage(), 'Class "SwooleTestClassA2" not found');
        echo "DONE\n";
    }

});
?>
--EXPECT--
DONE
