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

function skip_php_version_lower_than($require_version = '7.0')
{
    if (version_compare(PHP_VERSION, $require_version, '<')) {
        skip('need php version >= ' . $require_version);
    }
}

function skip_if_no_ssl()
{
    if (!defined("SWOOLE_SSL")) {
        skip('no ssl');
    }
}

function skip_if_no_async_redis()
{
    if (!class_exists("swoole_redis", false)) {
        skip('no async redis');
    }
}

function skip_if_no_http2()
{
    if (!class_exists("swoole_http2_reqeust", false)) {
        skip('no http2');
    }
}

function skip_if_darwin()
{
    if (stripos(PHP_OS, 'Darwin') !== false) {
        skip("no darwin");
    }
}

function skip_if_no_process_affinity()
{
    if (!method_exists(swoole_process::class, 'setaffinity')) {
        skip('no process affinity');
    }
}

function skip_if_in_travis(string $reason = 'not support in travis')
{
    skip($reason, file_exists('/.travisenv'));
}

function skip_if_in_docker(string $reason = 'not support in docker')
{
    skip($reason, file_exists('/.dockerenv'));
}

function skip_if_no_proxy()
{
    require_once __DIR__ . '/config.php';
    if (IS_IN_TRAVIS || check_tcp_port(HTTP_PROXY_HOST, HTTP_PROXY_PORT) !== 1) {
        skip('no http proxy available');
    }
}

function skip_deprecated()
{
    skip('it\'s the deprecated.', file_exists('/.travisenv'), SWOOLE_COLOR_WHITE);
}

(function () {
    if (stripos(__DIR__, 'redis') !== false) {
        skip_if_no_http2();
    } elseif (stripos(__DIR__, 'http2') !== false) {
        skip_if_no_http2();
    }
    skip_php_version_lower_than('7.0');
})();