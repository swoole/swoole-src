<?php
/**
 * This file is part of Swoole, for internal use only
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

require_once __DIR__ . '/functions.php';

/** ============== Env =============== */
define('IS_MAC_OS', stripos(PHP_OS, 'Darwin') !== false);
define('IS_IN_TRAVIS', !!getenv('TRAVIS') || file_exists('/.travisenv'));
define('IS_PHPTESTSING', !!getenv('PHPT'));
define('USE_VALGRIND', getenv('USE_ZEND_ALLOC') === '0');
define('HAS_SSL', defined("SWOOLE_SSL"));
define('HAS_ASYNC_REDIS', class_exists("swoole_redis", false));
define('HAS_HTTP2', class_exists("swoole_http2_request", false));
define('DEV_NULL', '/dev/null');

/** ============== Files ============== */
define('SOURCE_ROOT_PATH', __DIR__ . '/../../');
define('TESTS_ROOT_PATH', __DIR__ . '/../');
define('TESTS_API_PATH', TESTS_ROOT_PATH.'/include/api');
define('TESTS_LIB_PATH', TESTS_ROOT_PATH.'/include/lib');
define('TRAVIS_DIR_PATH', __DIR__ . '/../../travis/');
define('TEST_IMAGE', __DIR__ . '/../../examples/test.jpg');
define('TEST_LINK_IMAGE', __DIR__ . '/../../examples/test_link.jpg');
define('TEST_IMAGE2', __DIR__ . '/../../examples/logo.svg');
define('TEST_LOG_FILE', '/tmp/swoole.log');
define('TEST_PID_FILE', '/tmp/swoole.pid');
define('SSL_FILE_DIR', __DIR__ . '/ssl_certs/');
define('SSL_FILE_DIR2', __DIR__ . '/../include/api/ssl-ca');
define('DOCUMENT_ROOT', __DIR__ . '/../../examples/www');

/** ============ Servers ============ */
define('SERVER_MODE_RANDOM', array_random([SWOOLE_BASE, SWOOLE_PROCESS]));
define('UNIXSOCK_PATH', '/tmp/unix-sock-test.sock');

define('TCP_SERVER_HOST', '127.0.0.1');
define('TCP_SERVER_PORT', 9001);

define('HTTP_SERVER_HOST', '127.0.0.1');
define('HTTP_SERVER_PORT', 9002);
define('WEBSOCKET_SERVER_HOST', '127.0.0.1');
define('WEBSOCKET_SERVER_PORT', 9003);

define('UDP_SERVER_HOST', '127.0.0.1');
define('UDP_SERVER_PORT', 9003);

/** ============== MySQL ============== */
define('MYSQL_SERVER_PATH', getenv('MYSQL_SERVER_PATH') ?:
    (IS_IN_TRAVIS ? TRAVIS_DIR_PATH . '/data/run/mysqld/mysqld.sock' :
        (IS_MAC_OS ? '/tmp/mysql.sock' : '/var/run/mysqld/mysqld.sock')));
define('MYSQL_SERVER_HOST', getenv('MYSQL_SERVER_HOST') ?: (IS_IN_TRAVIS ? 'mysql' : '127.0.0.1'));
define('MYSQL_SERVER_PORT', (int)(getenv('MYSQL_SERVER_PORT') ?: 3306));
define('MYSQL_SERVER_USER', getenv('MYSQL_SERVER_USER') ?: 'root');
define('MYSQL_SERVER_PWD', getenv('MYSQL_SERVER_PWD') ?: 'root');
define('MYSQL_SERVER_DB', getenv('MYSQL_SERVER_DB') ?: 'test');

/** ============== Redis ============== */
define('REDIS_SERVER_PATH', getenv('REDIS_SERVER_PATH') ?:
    (IS_IN_TRAVIS ? TRAVIS_DIR_PATH . '/data/run/redis/redis.sock' :
        (IS_MAC_OS ? '/tmp/redis.sock' : '/var/run/redis/redis-server.sock')));
define('REDIS_SERVER_HOST', getenv('REDIS_SERVER_HOST') ?: (IS_IN_TRAVIS ? 'redis' : '127.0.0.1'));
define('REDIS_SERVER_PORT', (int)(getenv('REDIS_SERVER_PORT') ?: 6379));
define('REDIS_SERVER_PWD', getenv('REDIS_SERVER_PWD') ?: 'root');
define('REDIS_SERVER_DB', (int)(getenv('REDIS_SERVER_DB') ?: 0));

if (!getenv('SWOOLE_TEST_NO_DOCKER')) {
    if (!empty($info = `docker ps 2>&1 | grep httpbin 2>&1`) &&
        preg_match('/\s+?[^:]+:(\d+)->\d+\/tcp\s+/', $info, $matches) &&
        is_numeric($matches[1])) {
        define('HTTPBIN_SERVER_PORT_IN_DOCKER', (int)$matches[1]);
    }
}

/** ============== HttpBin ============== */
if (IS_IN_TRAVIS) {
    define('HTTPBIN_SERVER_HOST', 'httpbin');
    define('HTTPBIN_SERVER_PORT', 80);
    define('HTTPBIN_LOCALLY', true);
} elseif (defined('HTTPBIN_SERVER_PORT_IN_DOCKER')) {
    define('HTTPBIN_SERVER_HOST', '127.0.0.1');
    define('HTTPBIN_SERVER_PORT', HTTPBIN_SERVER_PORT_IN_DOCKER);
    define('HTTPBIN_LOCALLY', true);
} elseif (getenv('HTTPBIN_SERVER_HOST')) {
    define('HTTPBIN_SERVER_HOST', getenv('HTTPBIN_SERVER_HOST'));
    define('HTTPBIN_SERVER_PORT', (int)getenv('HTTPBIN_SERVER_PORT'));
    define('HTTPBIN_LOCALLY', true);
} else {
    define('HTTPBIN_SERVER_HOST', 'httpbin.org');
    define('HTTPBIN_SERVER_PORT', 80);
}

if (IS_IN_TRAVIS) {
    define('TEST_HTTP2_SERVERPUSH_URL', 'https://golang-h2demo:4430/serverpush');
} else {
    define('TEST_HTTP2_SERVERPUSH_URL', 'https://127.0.0.1:4430/serverpush');
}

/** =============== IP ================ */
define('IP_REGEX', '/^(?:[\d]{1,3}\.){3}[\d]{1,3}$/');

/** ============= Proxy ============== */
define('HTTP_PROXY_HOST', IS_IN_TRAVIS ? 'tinyproxy' : '127.0.0.1');
define('HTTP_PROXY_PORT', IS_IN_TRAVIS ? 8888 : (IS_MAC_OS ? 1087 : 8888));
define('SOCKS5_PROXY_HOST', IS_IN_TRAVIS ? 'socks5' : '127.0.0.1');
define('SOCKS5_PROXY_PORT', IS_MAC_OS ? 1086 : 1080);


/** ============== Pressure ============== */
define('PRESSURE_LOW', 1);
define('PRESSURE_MID', 2);
define('PRESSURE_NORMAL', 3);
define('PRESSURE_LEVEL',
    USE_VALGRIND ? (IS_IN_TRAVIS ? PRESSURE_LOW - 1 : PRESSURE_LOW) : ((IS_IN_TRAVIS || swoole_cpu_num() === 1) ? PRESSURE_MID : PRESSURE_NORMAL));

/** ============== Time ============== */
define('SERVER_PREHEATING_TIME', 0.1);
define('REQUESTS_WAIT_TIME', [0.005, 0.005, 0.05, 0.1][PRESSURE_LEVEL]);

/** ============== Times ============== */
define('MAX_CONCURRENCY', [16, 32, 64, 256][PRESSURE_LEVEL]);
define('MAX_CONCURRENCY_MID', [8, 16, 32, 128][PRESSURE_LEVEL]);
define('MAX_CONCURRENCY_LOW', [4, 8, 16, 64][PRESSURE_LEVEL]);
define('MAX_REQUESTS', [12, 24, 50, 100][PRESSURE_LEVEL]);
define('MAX_REQUESTS_MID', [8, 16, 32, 64][PRESSURE_LEVEL]);
define('MAX_REQUESTS_LOW', [4, 8, 10, 25][PRESSURE_LEVEL]);
define('MAX_LOOPS', [12, 24, 100, 1000][PRESSURE_LEVEL] * 1000);
define('MAX_PROCESS_NUM', [2, 4, 6, 8][PRESSURE_LEVEL]);
define('MAX_PACKET_NUM', [1024, 2048, 4096, 10000][PRESSURE_LEVEL]);

/** ============== FTP ============== */
define('FTP_HOST', IS_IN_TRAVIS ? 'ftp' : '127.0.0.1');
define('FTP_PORT', 21);
define('FTP_USER', 'admin');
define('FTP_PASS', 'admin');
