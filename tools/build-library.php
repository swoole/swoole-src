<?php
define('LIB_DIR', dirname(__DIR__) . '/library');
$list = glob(LIB_DIR . '/*.php');

$include_str = '';
$eval_str = '';

$comment = "/**
 * Generated code, do not modify
 */";

foreach ($list as $li) {
    $code = file_get_contents($li);
    $code = trim(preg_replace('/<\?php/', '', $code, 1));
    $code = str_replace(['\\', '"', "\n"], ['\\\\', '\"', " \\\n"], $code);

    $fname = basename($li, '.php');
    $h_file = '/swlib_' . $fname . '.h';
    $path = dirname($li) . $h_file;

    $var_name = "swlib_{$fname}";
    file_put_contents($path, "$comment\nstatic const char* {$var_name} = \"" . $code . ";\";\n");
    $include_str .= "#include \"library{$h_file}\"\n";
    $eval_str .= "zend::eval({$var_name});\n";
}

file_put_contents(LIB_DIR . '/_swlib_include.h', $comment . "\n" . $include_str);
file_put_contents(LIB_DIR . '/_swlib_eval.h', $comment . "\n" . $eval_str);
echo "generating swoole php library...\n";
