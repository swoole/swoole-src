<?php
define("TCP_SERVER_HOST", "127.0.0.1");
define("TCP_SERVER_PORT", 9001);

define("HTTP_SERVER_HOST", "127.0.0.1");
define("HTTP_SERVER_PORT", 9002);
define("WEBSOCKET_SERVER_HOST", "127.0.0.1");
define("WEBSOCKET_SERVER_PORT", 9003);

define("UNIXSOCK_SERVER_PATH", __DIR__ . "/unix-sock-test.sock");

define("UDP_SERVER_HOST", "127.0.0.1");
define("UDP_SERVER_PORT", "9003");

define("REDIS_SERVER_PATH", "");
define("REDIS_SERVER_HOST", "127.0.0.1");
define("REDIS_SERVER_PORT", 6379);

define("MYSQL_SERVER_HOST", "127.0.0.1");
define("MYSQL_SERVER_PORT", 3306);
define("MYSQL_SERVER_USER", "root");
define("MYSQL_SERVER_PWD", "root");
define("MYSQL_SERVER_DB", "test");

define("TEST_IMAGE", __DIR__ . "/../../examples/test.jpg");

define("IP_BAIDU", "180.97.33.107");

define('HTTP_PROXY_HOST', '127.0.0.1');
define('HTTP_PROXY_PORT', 8888);

define('TEST_LOG_FILE', '/tmp/swoole.log');

define('IS_MAC_OS', stripos(PHP_OS, 'Darwin') !== false);

define('SSL_FILE_DIR', __DIR__.'/api/swoole_http_server/localhost-ssl');
