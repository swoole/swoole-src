<?php

use Swoole\Memory\Pool;

$pool = new Pool(2 * 1024 * 1024, Pool::TYPE_RING, 1024);

/**
 * @var $p1 Swoole\Memory\Pool\Slice
 */
$p1 = $pool->alloc();
$p1->write("hello world");
echo $p1->read()."\n";
echo $p1->read(5, 6)."\n";
