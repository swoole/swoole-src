<?php
require_once __DIR__ . '/functions.php';

/** ============== Env =============== */
define('IS_MAC_OS', stripos(PHP_OS, 'Darwin') !== false);
define('IS_IN_TRAVIS', file_exists('/.travisenv'));

/** ============ Servers ============ */
define('TCP_SERVER_HOST', '127.0.0.1');
define('TCP_SERVER_PORT', 9001);

define('HTTP_SERVER_HOST', '127.0.0.1');
define('HTTP_SERVER_PORT', 9002);
define('WEBSOCKET_SERVER_HOST', '127.0.0.1');
define('WEBSOCKET_SERVER_PORT', 9003);

define('UNIXSOCK_SERVER_PATH', __DIR__ . '/unix-sock-test.sock');

define('UDP_SERVER_HOST', '127.0.0.1');
define('UDP_SERVER_PORT', '9003');

/** ============== MySQL ============== */
define('MYSQL_SERVER_HOST', IS_IN_TRAVIS ? 'mysql' : '127.0.0.1');
define('MYSQL_SERVER_PORT', 3306);
define('MYSQL_SERVER_USER', 'root');
define('MYSQL_SERVER_PWD', 'root');
define('MYSQL_SERVER_DB', 'test');

/** ============== Redis ============== */
define('REDIS_SERVER_PATH', "");
define('REDIS_SERVER_HOST', IS_IN_TRAVIS ? 'redis' : '127.0.0.1');
define('REDIS_SERVER_PORT', 6379);

/** =============== IP ================ */
define('IP_BAIDU', '180.97.33.107');

/** ============= Proxy ============== */
define('HTTP_PROXY_HOST', '127.0.0.1');
if (IS_MAC_OS) {
    define('HTTP_PROXY_PORT', 1087);
} else {
    define('HTTP_PROXY_PORT', 8888);
}

/** ============== Files ============== */
define('TEST_IMAGE', __DIR__ . '/../../examples/test.jpg');
define('TEST_LOG_FILE', '/tmp/swoole.log');
define('SSL_FILE_DIR', __DIR__ . '/api/swoole_http_server/localhost-ssl');

/** ============== Times ============== */
define('MAX_CONCURRENCY', IS_IN_TRAVIS ? 50 : 200);
define('MAX_CONCURRENCY_MID', IS_IN_TRAVIS ? 35 : 100);
define('MAX_CONCURRENCY_LOW', IS_IN_TRAVIS ? 20 : 50);
define('MAX_REQUESTS', IS_IN_TRAVIS ? 50 : 200);