#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

$git_files = swoole_git_files();
$git_files_map = [];
foreach ($git_files as $file) {
    $git_files_map[$file] = filesize(__DIR__ . "/../{$file}");
}
array_multisort($git_files_map, SORT_DESC);
$git_files_map = array_slice($git_files_map, 0, 36);
echo json_encode($git_files_map, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
