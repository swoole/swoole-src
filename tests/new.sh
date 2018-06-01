#!/usr/bin/env php
<?php
define('SWOOLE_COLOR_RED', 1);
define('SWOOLE_COLOR_GREEN', 2);
define('SWOOLE_COLOR_YELLOW', 3);
define('SWOOLE_COLOR_BLUE', 4);
define('SWOOLE_COLOR_MAGENTA', 5);
define('SWOOLE_COLOR_CYAN', 6);
define('SWOOLE_COLOR_WHITE', 7);
function swoole_color(string $content, int $color)
{
    return "\033[3{$color}m{$content}\033[0m";
}

if (empty($argv[1])) {
    error_filename:
    exit(
        swoole_color("Please enter the correct filename! e.g.:", SWOOLE_COLOR_RED) .
        swoole_color("\n\"/new ./swoole_coroutine/coro_sleep.phpt\"\n", SWOOLE_COLOR_MAGENTA)
    );
}

$filename = $argv[1];
$path = pathinfo($filename);
if (empty($path['dirname']) || empty($path['filename'])) {
    goto error_filename;
} else {
    $path['dirname'] = ltrim($path['dirname'], './'); // i know arg2 is list but it's no problem
    $filename = "{$path['dirname']}/{$path['filename']}.phpt";
}

//if dir not exist, create it
if (!is_dir(__DIR__ . "/{$path['dirname']}")) {
    mkdir($path['dirname'], 0755);
} elseif (file_exists($filename)) {
    echo swoole_color("The file is exist, if you want to overwrite it? [y/n]: ", SWOOLE_COLOR_YELLOW);
    if (trim(fgets(STDIN)) !== 'y') {
        exit;
    }
}


//calc dir deep
$deep = 0;
$temp = $filename;
while (($temp = dirname($temp)) !== '.') {
    $deep++;
}
if ($deep < 1) {
    goto error_filename;
}

$template = file_get_contents(__DIR__ . '/template.phpt');
$replacement = [];
$replacement['dir_deep'] = str_repeat('/..', $deep);
echo swoole_color("[Test name]: ", SWOOLE_COLOR_BLUE);
$replacement['test_name'] = trim(fgets(STDIN));
echo swoole_color("[Test intro]: ", SWOOLE_COLOR_BLUE);
$replacement['test_intro'] = trim(fgets(STDIN));
foreach ($replacement as $key => $value) {
    $template = str_replace("{{{$key}}}", $value, $template);
}

if (file_put_contents($filename, $template)) {
    echo swoole_color("Generate the test file successfully!\n", SWOOLE_COLOR_GREEN) .
        "[" . __DIR__ . "/$filename]";
    if (\stripos(PHP_OS, 'Darwin') !== false) {
        //MacOS
        $pstorm = '/usr/local/bin/pstorm';
        if (file_exists($pstorm) || (
                file_exists('/Applications/PhpStorm.app') &&
                file_put_contents($pstorm, file_get_contents(__DIR__ . '/include/macos/phpstorm.py')) &&
                chmod($pstorm, 0744)
            )
        ) {
            shell_exec("/usr/local/bin/phpstorm {$filename}");
        }
    }
} else {
    exit("\nGenerate the test file failed!");
}
