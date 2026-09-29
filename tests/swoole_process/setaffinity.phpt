--TEST--
swoole_process: setAffinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$original = Swoole\Process::getAffinity();
$cpu = $original[0];

try {
    Assert::true(Swoole\Process::setAffinity([(string) $cpu]));
    Assert::same(Swoole\Process::getAffinity(), [$cpu]);

    if (count($original) > 1) {
        Assert::true(Swoole\Process::setAffinity([$original[0], $original[1]]));
        Assert::same(Swoole\Process::getAffinity(), [$original[0], $original[1]]);
    }

    $warning = null;
    set_error_handler(function ($errno, $message) use (&$warning) {
        $warning = $message;
        return true;
    });
    try {
        Assert::false(Swoole\Process::setAffinity([$cpu, -1]));
    } finally {
        restore_error_handler();
    }
    Assert::contains($warning, 'invalid cpu id [-1]');
} finally {
    @Swoole\Process::setAffinity($original);
}
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
