--TEST--
swoole_atomic: wakeup & wait
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
$atomic = new swoole_atomic;
const N = 4;

$workers = [];

for ($i = 0; $i < 4; $i++)
{
    $p = new swoole_process(function () use ($atomic)
    {
        $atomic->wait();
        echo "Child OK\n";
    });
    $p->start();
    $workers[$i] = $p;
}

usleep(200000);
echo "Master OK\n";
$atomic->wakeup(N);

for ($i = 0; $i < 4; $i++)
{
    $status = swoole_process::wait();
}
?>

--EXPECT--
Master OK
Child OK
Child OK
Child OK
Child OK
