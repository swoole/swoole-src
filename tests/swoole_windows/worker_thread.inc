<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$args = Thread::getArguments();
[$id, $queue] = $args;
$queue->push("Thread #{$id}\n");
$rs = file_get_contents('https://' . TEST_DOMAIN_3 . '/');
Assert::assert(is_string($rs));
$queue->push(var_export(strlen($rs), true));
