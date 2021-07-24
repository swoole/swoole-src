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

function createDirectories()
{
    $barrier = Barrier::make();
    $first   = "/".rand(0, 1000);
    $second  = "/".rand(0, 1000);
    $third   = "/".rand(0, 1000)."/";

    for ($i = 0; $i < 5; $i++) {
        Coroutine::create(static function () use ($i, $first, $second, $third, $barrier) {
            if (mkdir($directory = $first.$second.$third.$i, 0755, true) && is_dir($directory)) {
                rmdir($first.$second.$third.$i);
                echo "SUCCESS".PHP_EOL;
            }
        });
    }
    Barrier::wait($barrier);
    rmdir($first.$second.$third);
    rmdir($first.$second);
    rmdir($first);
}


run(function () {
    createDirectories();
});

Swoole\Runtime::enableCoroutine(false);
createDirectories();
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
