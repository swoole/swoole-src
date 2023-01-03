<?php
define('SWOOLE_COLOR_RED', 1);
define('SWOOLE_COLOR_GREEN', 2);
define('SWOOLE_COLOR_YELLOW', 3);
define('SWOOLE_COLOR_BLUE', 4);
define('SWOOLE_COLOR_MAGENTA', 5);
define('SWOOLE_COLOR_CYAN', 6);
define('SWOOLE_COLOR_WHITE', 7);

skip(
    'Linux only',
    substr(PHP_OS, 0, 3) === 'WIN',
    SWOOLE_COLOR_RED
);
skip(
    'Swoole extension is required',
    !extension_loaded('swoole'),
    SWOOLE_COLOR_RED
);
skip(
    'Please set "swoole.use_shortname = On"',
    !SWOOLE_USE_SHORTNAME,
    SWOOLE_COLOR_RED
);

(function () {
    global $argv;
    skip_if_php_version_lower_than('7.0');
    if (!getenv('PHPT') && substr($argv[0], -4) === '.php') {
        skip('please read ' . dirname(dirname(__FILE__)) . '/README.md and try again');
    }
    if (preg_match('#/(swoole_[^/]+)/#', $_SERVER['SCRIPT_FILENAME'], $dir)) {
        $dir = $dir[1];
        if (stripos($dir, 'http2') !== false) {
            skip_if_no_http2();
        }
    }
})();

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

function skip_if_php_version_lower_than($require_version = '7.0')
{
    if (version_compare(PHP_VERSION, $require_version, '<')) {
        skip('need php version >= ' . $require_version);
    }
}

function skip_if_php_version_between($a, $b)
{
    if (version_compare(PHP_VERSION, $a, '>=') && version_compare(PHP_VERSION, $b, '<=')) {
        skip("unsupported php version between {$a} and {$b}");
    }
}

function skip_if_not_debug_version()
{
    skip('only in swoole debug version', !SWOOLE_DEBUG);
}

function skip_if_ini_bool_equal_to(string $name, bool $value)
{
    if (((bool)ini_get($name)) === $value) {
        $value = $value ? 'enable' : 'disable';
        skip("{$name} is {$value}");
    }
}

function skip_if_constant_not_defined(string $constant_name)
{
    require_once __DIR__ . '/config.php';
    skip("{$constant_name} is not defined", !defined($constant_name));
}

function skip_if_function_not_exist(string $function_name)
{
    skip("{$function_name} not exist", !function_exists($function_name));
}

function skip_if_class_not_exist(string $class_name)
{
    skip("{$class_name} not exist", !class_exists($class_name, false));
}

function skip_if_extension_not_exist(string $extension_name)
{
    skip("{$extension_name} not exist", !extension_loaded($extension_name));
}

function skip_if_file_not_exist(string $filename)
{
    skip("file {$filename} is not exist", !file_exists($filename));
}

function skip_if_command_not_found(string $command)
{
    skip("command {$command} not found", empty(`{$command} --help 2>&1 | grep -i usage`));
}

function skip_if_no_ssl()
{
    if (!defined("SWOOLE_SSL")) {
        skip('no ssl');
    }
}

function skip_if_openssl_version_lower_than($version = '1.0.0')
{
    skip_if_no_ssl();
    $exist = preg_match('/openssl => openssl ([\d\.]+)/i', `php --ri swoole`, $match);
    assert($exist);
    if (version_compare($match[1], $version, '<')) {
        skip("openssl version {$match[1]} is lower than {$version}");
    }
}

function skip_if_no_http2()
{
    skip('no http2', !class_exists(Swoole\Http2\Request::class, false));
}


function skip_if_no_ipv6()
{
    skip('no ipv6 address', !@stream_socket_server('tcp://[::1]:0'));
}

function skip_if_no_top()
{
    skip_if_darwin();
    skip('top provided by busybox (not support)', !empty(`top --help 2>&1 | grep -i busybox`));
    skip('no top', empty(`top help 2>&1 | grep -i usage`));
}

function skip_if_darwin()
{
    skip('not support on darwin', stripos(PHP_OS, 'Darwin') !== false);
}

function skip_if_musl_libc()
{
    skip('not support when use musl libc', !empty(`ldd 2>&1 | grep -i musl`));
}

function skip_if_no_process_affinity()
{
    skip('no process affinity', !method_exists(Swoole\Process::class, 'setaffinity'));
}

function skip_if_in_valgrind(string $reason = 'valgrind is too slow')
{
    skip($reason, getenv('USE_ZEND_ALLOC') === '0');
}

function skip_if_in_travis(string $reason = 'not support in travis')
{
    skip($reason, file_exists('/.travisenv'));
}

function skip_if_in_docker(string $reason = 'not support in docker')
{
    skip($reason, file_exists('/.dockerenv'));
}

function skip_if_offline()
{
    if (getenv("SKIP_ONLINE_TESTS")) {
        skip('it\'s the online test but you are offline');
    }
}

function skip_if_no_proxy(string $host, string $port)
{
    skip('no available proxy', !check_tcp_port($host, $port));
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
    try {
        new PDO(
            "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
            MYSQL_SERVER_USER, MYSQL_SERVER_PWD
        );
    } catch (\PDOException $e) {
        if ($e->getCode() === 2054) {
            skip('pdo auth not support');
        }
    }
}

function skip_if_not_mysql8()
{
    require_once __DIR__ . '/config.php';
    $skip = true;
    Swoole\Coroutine\run(function () use (&$skip) {
        try {
            if (preg_match(
                '/caching_sha2_password/',
                httpGetBody('http://' . MYSQL_SERVER_HOST . ':' . MYSQL_SERVER_PORT))
            ) {
                $skip = false;
            }
        } catch (Throwable $throwable) {
            // ignored
        }
    });
    if ($skip) {
        skip('require mysql8');
    }
}

function skip_if_not_redis5()
{
    require_once __DIR__ . '/config.php';
    $skip = false;
    go(function () use (&$skip) {
        $redis = new Swoole\Coroutine\Redis();
        $redis->setOptions(['compatibility_mode' => true]);
        $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
        $info = $redis->eval("return redis.call('info')");
        if (preg_match('/redis_version:(\d+)/U', $info, $version)) {
            if ($version[1] < 5) {
                $skip = true;
            }
        }
    });
    Swoole\Event::wait();
    if ($skip) {
        skip('require redis5');
    }
}

function skip_unsupported(string $message = '')
{
    skip($message ?: 'the test cannot continue to work for some implementation reasons');
}

function skip_if_no_ftp()
{
    require_once __DIR__ . '/config.php';
    skip('no available proxy', !check_tcp_port(FTP_HOST, FTP_PORT));
}
