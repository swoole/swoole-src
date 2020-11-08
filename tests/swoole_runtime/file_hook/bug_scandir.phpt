--TEST--
swoole_runtime/file_hook: bug #3792
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$testDir = sys_get_temp_dir() . '/swoole_scandir_bug';

if (!is_dir($testDir)) {
    mkdir($testDir);
}
for ($i = 0; $i++ < 3;) {
    touch("{$testDir}/{$i}.txt");
}

\Swoole\Runtime::enableCoroutine(true);
\Swoole\Coroutine\run(
    function () use ($testDir) {
        for ($i = 0; $i < MAX_CONCURRENCY; $i++) {
            go(
                function () use ($testDir) {
                    $files = scandir($testDir);
                    Assert::same($files, [
                        '.',
                        '..',
                        '1.txt',
                        '2.txt',
                        '3.txt',
                    ]);
                }
            );
        }
    }
);

echo "DONE\n";

?>
--EXPECT--
DONE
