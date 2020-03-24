<?php

namespace SwooleBench;

function get_response($reqData)
{
    return 'Swoole: ' . $reqData;
}

if (!defined('')) {
    define('SWOOLE_COLOR_RED', 1);
    define('SWOOLE_COLOR_GREEN', 2);
    define('SWOOLE_COLOR_YELLOW', 3);
    define('SWOOLE_COLOR_BLUE', 4);
    define('SWOOLE_COLOR_MAGENTA', 5);
    define('SWOOLE_COLOR_CYAN', 6);
    define('SWOOLE_COLOR_WHITE', 7);
}

function color(string $content, int $color): string
{
    return "\033[3{$color}m{$content}\033[0m";
}
