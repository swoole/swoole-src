<?php

use Swoole\Thread\Map;

$map = new Map;
$c = 1;
$threads = [];

for ($i = 0; $i < $c; $i++) {
    $threads[] = new Swoole\Thread('benchmark.php', 'thread-' . ($i + 1), $map);
}

for ($i = 0; $i < $c; $i++) {
    $threads[$i]->join();
}

