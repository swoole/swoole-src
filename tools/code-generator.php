#!/usr/bin/env php
<?php
require __DIR__ . '/functions.php';

// generate ERROR constants
$swoole_c = __DIR__ . '/../swoole.c';
$swoole_c_content = file_get_contents($swoole_c);
$error_h = __DIR__ . '/../include/error.h';
$error_h_content = file_get_contents($error_h);
preg_match_all('/SW_ERROR_[0-9A-Z_]+/', $error_h_content, $matches, PREG_PATTERN_ORDER);
$output = '';
foreach ($matches[0] as $match) {
    $constant = str_replace('SW_', '', $match);
    $output .= "    SWOOLE_DEFINE({$constant});\n";
}
$swoole_c_content = preg_replace('/ *?(?:SWOOLE_DEFINE\(ERROR_[0-9A-Z_]+?\);\n *)+/', $output, $swoole_c_content);
file_put_contents($swoole_c, $swoole_c_content);

swoole_success('Generate source codes OK!');
