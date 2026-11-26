--TEST--
swoole_process: getAffinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
$original = Process::getAffinity();
Assert::notEmpty($original);
$cpu = [$original[array_key_last($original)]];

try {
    Assert::true(Process::setAffinity($cpu));
    Assert::same(Process::getAffinity(), $cpu);
} finally {
    Assert::true(Process::setAffinity($original));
}
Assert::same(Process::getAffinity(), $original);
?>
--EXPECT--
