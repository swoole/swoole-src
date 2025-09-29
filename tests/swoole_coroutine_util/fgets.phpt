--TEST--
swoole_coroutine_util: fgets
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $file = __DIR__ . '/../../examples/server/mixed.php';

    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    $coroutine = [];
    $fp = fopen($file, "r");
    while (!feof($fp)) {
        $coroutine [] = fgets($fp);
    }

    Swoole\Runtime::enableCoroutine(false);
    $standard = [];
    $fp = fopen($file, "r");
    while (!feof($fp)) {
        $standard [] = fgets($fp);
    }

    Assert::same($standard, $coroutine);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
