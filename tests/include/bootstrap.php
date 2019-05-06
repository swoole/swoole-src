<?php
require_once __DIR__ . '/config.php'; // (`once` because it may required in skip when we run phpt)

// PHP settings
error_reporting(E_ALL ^ E_DEPRECATED);
ini_set('memory_limit', '1024M');
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 0);

// Swoole settings
swoole_async_set([
    'socket_dontwait' => 1,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
]);
Co::set([
    'socket_timeout' => 5
]);
if (empty(getenv('SWOOLE_DEBUG'))) {
    Co::set([
        'log_level' => SWOOLE_LOG_INFO,
        'trace_flags' => 0,
    ]);
}

// Components
(function () {
    require __DIR__ . '/lib/vendor/autoload.php';

    class Assert extends \Swoole\Assert
    {
        protected static $throwException = false;
    }
})();
