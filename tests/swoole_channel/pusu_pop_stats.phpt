--TEST--
swoole_channel: push & pop & stats

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Channel;

const N = 100;
$chan = new Channel(1024 * 256);

$worker_num = 4;
$workers = array();

for ($i = 0; $i < N; $i++)
{
    $n = rand(100, 200);
    $chan->push(['value' => str_repeat('A', $n), 'len' => $n]);
}

$stats = $chan->stats();
assert($stats['queue_num'] == N);

for ($i = 0; $i < N; $i++)
{
    $ret = $chan->pop();
    assert(is_array($ret));
}
?>
--EXPECT--