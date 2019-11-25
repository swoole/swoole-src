#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

$config_m4 = __DIR__ . '/../config.m4';
$config_m4_content = file_get_contents($config_m4);
$source_list = swoole_source_list(['h' => false]);

// config.m4
$output = space(8) . implode(" \\\n" . space(8), $source_list);
$output = preg_replace('/(swoole_source_file=[^\n]+\n)[^"]+"/', "$1{$output}\"", $config_m4_content, 1, $count);
if ($count !== 1) {
    swoole_error('Update source files in config.m4 error!');
}
file_put_contents($config_m4, $output);
swoole_ok('Generate config.m4 ok!');

// cmake
// $cmake_lists = __DIR__ . '/../CMakeLists.txt';
// $cmake_lists_content = file_get_contents($cmake_lists);
// $output = space(4) . implode("\n" . space(4), $source_list) . "\n";
// $output = preg_replace('/(set\(SOURCE_FILES\n)[^)]+\)/', "$1{$output})", $cmake_lists_content, 1, $count);
// if ($count !== 1) {
//     swoole_error('Update source files in CMakeLists.txt error!');
// }
// file_put_contents($cmake_lists, $output);
// swoole_ok('Generate CMakeLists.txt ok!');

swoole_success('Config generator successfully done!');
