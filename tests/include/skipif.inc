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

function skip_php_version_between($a, $b)
{
    if (version_compare(PHP_VERSION, $a, '>=') && version_compare(PHP_VERSION, $b, '<=')) {
        skip("unsupported php version between {$a} and {$b}");
    }
}

function skip_if_class_not_exist(string $class_name)
{
    if (!class_exists($class_name, false)) {
        skip("{$class_name} not exist");
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
        skip("not support on darwin");
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

function skip_if_no_proxy(string $host, string $port)
{
    if (IS_IN_TRAVIS || check_tcp_port($host, $port) !== 1) {
        skip('no available proxy');
    }
}

function skip_if_no_http_proxy()
{
    require_once __DIR__ . '/config.php';
    skip_if_no_proxy(HTTP_PROXY_HOST, HTTP_PROXY_PORT);
}

function skip_if_no_socks5_proxy()
{
    require_once __DIR__ . '/config.php';
    skip_if_no_proxy(SOCKS5_PROXY_HOST, SOCKS5_PROXY_PORT);
}

function skip_if_pdo_not_support_mysql8()
{
    require_once __DIR__ . '/config.php';
    if (IS_IN_TRAVIS) {
        try {
            new PDO(
                "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                MYSQL_SERVER_USER, MYSQL_SERVER_PWD
            );
        } catch (\PDOException $e) {
            if ($e->getCode() === 2054) {
                skip('pdo auth not support.');
            }
        }
    }
}

function skip_if_not_mysql8()
{
    require_once __DIR__ . '/config.php';
    if (!preg_match(
        '/caching_sha2_password/',
        $r = curlGet('http://' . MYSQL_SERVER_HOST . ':' . MYSQL_SERVER_PORT))
    ) {
        skip('require mysql8.');
    }
    var_dump($r);
}

function skip_deprecated()
{
    skip('it\'s the deprecated.', file_exists('/.travisenv'), SWOOLE_COLOR_WHITE);
}

(function () {
    if (preg_match('#\/(swoole_[^\/]+)\/#', $_SERVER['SCRIPT_FILENAME'], $dir)) {
        $dir = $dir[1];
        if (stripos($dir, 'redis') !== false) {
            skip_if_no_async_redis();
        } elseif (stripos($dir, 'http2') !== false) {
            skip_if_no_http2();
        } // it should be removed after php73 released
        elseif (PHP_VERSION_ID === 70300 && version_compare(PHP_VERSION, '7.3.0RC5', '<')) {
            // it should be removed after php73 released
            if (stripos($dir, 'runtime') !== false || stripos($dir, 'serialize') !== false) {
                skip('unsupported php dev version');
            }
        }
        skip_php_version_lower_than('7.0');
    }
})();
