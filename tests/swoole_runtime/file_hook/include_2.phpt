--TEST--
swoole_runtime/file_hook: include
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

spl_autoload_register(function ($class) {
    if ($class == 'SwooleTestClassA') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/A.php';
    } elseif ($class == 'SwooleTestClassB') {
        require TESTS_ROOT_PATH . '/include/api/test_classes/B.php';
    }
});

Swoole\Coroutine\run(function () {
    for ($i = 0; $i < 4; $i++) {
        go(function () use ($i) {
            echo "$i-1\n";
            Assert::eq(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_ALL);
            if ($i % 2 == 1) {
                Assert::assert(class_exists(SwooleTestClassB::class));
            } else {
                Assert::assert(class_exists(SwooleTestClassA::class));
            }
            echo "$i-2\n";
        });
    }
});

?>
--EXPECT--
0-1
0-2
1-1
1-2
2-1
2-2
3-1
3-2
