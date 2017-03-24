<?php
$dir = dirname(__DIR__);
define('SPACE_4', str_repeat(' ', 4));
define('SPACE_8', SPACE_4.SPACE_4);
$src = file_get_contents($dir . '/PHP_API.hpp');
$r = preg_match('/\#define\s+MAX_ARGC\s+(\d+)/', $src, $match);
if (!$r) {
    exit("no MAX_ARGC\n");
}

$maxArgc = $match[1];

//生成函数执行代码
$out = '';
for ($i = 1; $i <= $maxArgc; $i++) {
    $out .= 'Variant exec(const char *func, ';
    $list = [];
    for ($j = 1; $j <= $i; $j++) {
        $list[] = 'Variant v' . $j;
    }
    $out .= implode(', ', $list);
    $out .= ")\n{\n";
    $out .= SPACE_4."Variant _func(func);\n".SPACE_4."Array args;\n";
    for ($j = 1; $j <= $i; $j++) {
        $out .= SPACE_4."args.append(v" . ($j).".ptr());\n";
    }
    $out .= SPACE_4."return _call(NULL, _func.ptr(), args);\n}\n";
}
$exec_function_code = $out;

//生成对象方法执行代码
$out = '';
for ($i = 1; $i <= $maxArgc; $i++) {
    $out .= SPACE_4.'Variant exec(const char *func, ';
    $list = [];
    for ($j = 1; $j <= $i; $j++) {
        $list[] = 'Variant v' . $j;
    }
    $out .= implode(', ', $list);
    $out .= ")\n".SPACE_4."{\n";
    $out .= SPACE_8."Variant _func(func);\n".SPACE_8."Array args;\n";
    for ($j = 1; $j <= $i; $j++) {
        $out .= SPACE_8."args.append(v" . ($j).".ptr());\n";
    }
    $out .= SPACE_8."return _call(ptr(), _func.ptr(), args);\n".SPACE_4."}\n";
}
$exec_method_code = $out;

$pos1 = strpos($src, '/*generater-1*/');
$pos2 = strpos($src, '/*generater-2*/');
$pos3 = strpos($src, '/*generater-3*/');
$pos4 = strpos($src, '/*generater-4*/');


$s1 = substr($src, 0, $pos1);
$s2 = substr($src, $pos2 + strlen('/*generater-2*/'), $pos3 - $pos2 - strlen('/*generater-3*/'));
$s3 = substr($src, $pos4 + strlen('/*generater-3*/'), $pos4);

$src = trim($s1) . "\n/*generater-1*/\n" . trim($exec_function_code) . "\n/*generater-2*/\n" .
    trim($s2) . "\n" . SPACE_4 . "/*generater-3*/\n" . SPACE_4 . trim($exec_method_code) . "\n" . SPACE_4 . "/*generater-4*/\n" . SPACE_4 . trim($s3) . "\n\n";
file_put_contents($dir . '/PHP_API.hpp', $src);