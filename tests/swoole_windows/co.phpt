--TEST--
swoole_windows: coroutine sleep
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

echo "run\n";

run(function () {
    echo "sleep begin\n";
    usleep(100_000);
    echo "sleep end\n";
});
?>
--EXPECT--
run
sleep begin
sleep end
