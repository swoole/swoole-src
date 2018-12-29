<?php
require_once __DIR__ . '/config.php'; // (`once` because it may required in skip when we run phpt)

error_reporting(E_ALL ^ E_DEPRECATED);
ini_set('memory_limit', '1024M');
ini_set("assert.active", 1);
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 0);
assert_options(ASSERT_QUIET_EVAL, 0);

swoole_async_set([
    'socket_dontwait' => 1,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
]);

co::set([
    'socket_timeout' => 5
]);

if (empty(getenv('SWOOLE_DEBUG'))) {
    if (method_exists('co', 'set')) {
        co::set([
            'log_level' => SWOOLE_LOG_INFO,
            'trace_flags' => 0,
        ]);
    }
}
