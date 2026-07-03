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
}

for ($i = 0; $i < $c; $i++) {
    $threads[$i]->join();
}

$results = [];
for ($i = 0; $i < $c; $i++) {
    $result = $queue->pop();
    $results[$result['id']] = $result['length'];
}
ksort($results);

foreach ($results as $id => $length) {
    echo "Thread #{$id}\n";
    var_dump($length);
}
?>
--EXPECTF--
Thread #0
int(%d)
Thread #1
int(%d)
Thread #2
int(%d)
Thread #3
int(%d)
