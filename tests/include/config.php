<?php
require_once __DIR__ . '/functions.php';

/** ============== Env =============== */
define('IS_MAC_OS', stripos(PHP_OS, 'Darwin') !== false);
define('IS_IN_TRAVIS', file_exists('/.travisenv'));
define('IS_PHPTESTSING', !!getenv('PHPT'));
define('USE_VALGRIND', getenv('USE_ZEND_ALLOC') === '0');
define('HAS_SSL', defined("SWOOLE_SSL"));
define('HAS_ASYNC_REDIS', class_exists("swoole_redis", false));
define('HAS_HTTP2', class_exists("swoole_http2_request", false));

/** ============== Files ============== */
define('SOURCE_ROOT_PATH', __DIR__ . '/../../');
define('TRAVIS_DIR_PATH', __DIR__ . '/../../travis/');
define('TEST_IMAGE', __DIR__ . '/../../examples/test.jpg');
define('TEST_LOG_FILE', '/tmp/swoole.log');
define('TEST_PID_FILE', '/tmp/swoole.pid');
define('SSL_FILE_DIR', __DIR__ . '/api/swoole_http_server/localhost-ssl');

/** ============ Servers ============ */
define('SERVER_MODE_RANDOM', array_random([SWOOLE_BASE, SWOOLE_PROCESS]));

define('TCP_SERVER_HOST', '127.0.0.1');
define('TCP_SERVER_PORT', 9001);

define('HTTP_SERVER_HOST', '127.0.0.1');
define('HTTP_SERVER_PORT', 9002);
define('WEBSOCKET_SERVER_HOST', '127.0.0.1');
define('WEBSOCKET_SERVER_PORT', 9003);

define('UNIXSOCK_PATH', '/tmp/unix-sock-test.sock');

define('UDP_SERVER_HOST', '127.0.0.1');
define('UDP_SERVER_PORT', '9003');

/** ============== MySQL ============== */
define('MYSQL_SERVER_HOST', IS_IN_TRAVIS ? 'mysql' : '127.0.0.1');
define('MYSQL_SERVER_PORT', 3306);
define('MYSQL_SERVER_USER', 'root');
define('MYSQL_SERVER_PWD', 'root');
define('MYSQL_SERVER_DB', 'test');

/** ============== Redis ============== */
define('REDIS_SERVER_PATH',
    IS_IN_TRAVIS ? TRAVIS_DIR_PATH . '/data/redis/redis.sock' : (IS_MAC_OS ? '/tmp/redis.sock' : '/var/run/redis/redis-server.sock')
);
define('REDIS_SERVER_HOST', IS_IN_TRAVIS ? 'redis' : '127.0.0.1');
define('REDIS_SERVER_PORT', 6379);

/** =============== IP ================ */
define('IP_REGEX', '/^(?:[\d]{1,3}\.){3}[\d]{1,3}$/');
define('IP_BAIDU', '180.97.33.107');

/** ============= Proxy ============== */
define('HTTP_PROXY_HOST', '127.0.0.1');
define('HTTP_PROXY_PORT', IS_MAC_OS ? 1087 : 8888);
define('SOCKS5_PROXY_HOST', '127.0.0.1');
define('SOCKS5_PROXY_PORT', IS_MAC_OS ? 1086 : 1080);

/** ============== Times ============== */
define('PRESSURE_LEVEL', USE_VALGRIND ? 1 : IS_IN_TRAVIS ? 2 : 3);
define('MAX_CONCURRENCY', [16, 32, 64, 256][PRESSURE_LEVEL]);
define('MAX_CONCURRENCY_MID', [8, 16, 32, 128][PRESSURE_LEVEL]);
define('MAX_CONCURRENCY_LOW', [4, 8, 16, 64][PRESSURE_LEVEL]);
define('MAX_REQUESTS', [12, 24, 50, 100][PRESSURE_LEVEL]);
define('MAX_REQUESTS_LOW', [4, 8, 10, 25][PRESSURE_LEVEL]);
define('MAX_LOOPS', [12, 24, 100, 1000][PRESSURE_LEVEL] * 1000);
define('MAX_PROCESS_NUM', [2, 4, 6, 8][PRESSURE_LEVEL]);
