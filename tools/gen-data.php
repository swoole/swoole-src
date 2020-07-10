#!/usr/bin/env php
<?php
if (!empty($argv[1])) {
    $file = $argv[1];
} else {
    $file = __DIR__ . "/test.txt";
}

$op =

$fp = fopen($file, "w");
ftruncate($fp, 0);
fwrite($fp, str_repeat('A', 1024));
fwrite($fp, str_repeat('B', 1024));
fwrite($fp, str_repeat('C', 256) . "\n");
fclose($fp);