--TEST--
swoole_windows: thread fetch
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
if (!class_exists(Swoole\Thread::class, false)) {
    die('skip thread support not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$c = 4;
$queue = new Swoole\Thread\Queue();
$threads = [];

for ($i = 0; $i < $c; $i++) {
    $threads[$i] = new Thread(__DIR__ . '/worker_thread.inc', $i, $queue);
    var_dump($threads[$i]);
}

for ($i = 0; $i < $c; $i++) {
    $threads[$i]->join();
    var_dump($threads[$i]);
}

while(!$queue->empty()) {
    echo $queue->pop();
}
?>
--EXPECT--
Thread #0
int(5)
Thread #1
int(5)
Thread #2
int(5)
Thread #3
int(5)
