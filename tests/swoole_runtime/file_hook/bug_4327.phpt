--TEST--
mkdir failed when coroutines: bug #4372
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php

use Swoole\Coroutine;
use Swoole\Coroutine\Barrier;
use function Swoole\Coroutine\run;

require __DIR__.'/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine($flags = SWOOLE_HOOK_ALL);

run(function () {
    $barrier = Barrier::make();
    $baseDir = __DIR__.DIRECTORY_SEPARATOR.rand(1000, 9999).DIRECTORY_SEPARATOR;

    for ($i = 0; $i < 10; $i++) {
        Coroutine::create(static function () use ($i, $baseDir, $barrier) {
            if (!mkdir($directory = $baseDir.$i, 0755, true) && !is_dir($directory)) {
                rmdir($directory);
                echo "SUCCESS".PHP_EOL;
            }
        });
    }
    Barrier::wait($barrier);
    rmdir($baseDir);
});
?>

--EXPECT--
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS

