<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$args = Thread::getArguments();
[$id, $queue] = $args;
$rs = file_get_contents('https://' . TEST_DOMAIN_3 . '/');
Assert::assert(is_string($rs));
$queue->push(['id' => $id, 'length' => strlen($rs)]);
