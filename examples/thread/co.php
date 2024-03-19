<?php
$t1 = Swoole\Thread::run('mt.php', ['thread-1'], PHP_OS);
$t2 = Swoole\Thread::run('mt.php', ['thread-2'], PHP_OS);

var_dump($t1->id);
var_dump($t2->id);

$t1->join();
$t2->join();

