--TEST--
swoole_coroutine: autoload
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

spl_autoload_register(function ($class) {
    co::sleep(0.001); // coroutine context switch
    if ($class == 'SwooleTestClassA') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/A.php';
    }
});

Swoole\Coroutine\run(function () {
    for ($i = 0; $i < 2; ++$i)
    {
        go(static function (): void {
            var_dump(new SwooleTestClassA());
        });
    }
});

?>
--EXPECTF--
object(SwooleTestClassA)#%d (0) {
}
object(SwooleTestClassA)#%d (0) {
}
