<?php
if (substr(PHP_OS, 0, 3) == 'WIN') {
    exit('skip for Windows');
}
if (!extension_loaded('swoole')) {
    exit('skip swoole extension is required');
}

define('SWOOLE_COLOR_RED', 1);
define('SWOOLE_COLOR_GREEN', 2);
define('SWOOLE_COLOR_YELLOW', 3);
define('SWOOLE_COLOR_BLUE', 4);
define('SWOOLE_COLOR_MAGENTA', 5);
define('SWOOLE_COLOR_CYAN', 6);
define('SWOOLE_COLOR_WHITE', 7);

function swoole_color(string $content, int $color): string
{
    return "\033[3{$color}m{$content}\033[0m";
}

function skip(string $reason, bool $is_skip = true, int $color = SWOOLE_COLOR_YELLOW)
{
    if ($is_skip) {
        exit('skip ' . swoole_color($reason, $color));
    }
}

function skip_if_darwin()
{
    exit("skip for Darwin");
}

function skip_if_in_docker(string $reason = 'not support in docker')
{
    skip($reason, file_exists('/.dockerenv'));
}

function skip_if_no_proxy()
{
    require_once __DIR__ . '/../config.php';
    if (IS_IN_DOCKER || check_tcp_port(HTTP_PROXY_HOST, HTTP_PROXY_PORT) !== 1) {
        skip('no http proxy available');
    }
}

function skip_deprecated()
{
    skip('it\'s the deprecated.', true, SWOOLE_COLOR_WHITE);
}