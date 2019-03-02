<?php
require_once __DIR__ . '/config.php'; // (`once` because it may required in skip when we run phpt)

error_reporting(E_ALL ^ E_DEPRECATED);
ini_set('memory_limit', '1024M');
ini_set('assert.active', 1);
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 0);
assert_options(ASSERT_QUIET_EVAL, 0);

swoole_async_set([
    'socket_dontwait' => 1,
    'disable_dns_cache' => true,
    'dns_lookup_random' => true,
]);
Co::set([
    'socket_timeout' => 5
]);
if (empty(getenv('SWOOLE_DEBUG')) && method_exists('Co', 'set')) {
    Co::set([
        'log_level' => SWOOLE_LOG_INFO,
        'trace_flags' => 0,
    ]);
}

if (!is_dir(__DIR__ . '/lib/vendor')) {
    $composer_dir = __DIR__ . '/lib';
    $composer_info = `cd {$composer_dir} && composer install 2>&1`;
    if (strpos($composer_info, 'Generating autoload files') === false) {
        throw new RuntimeException('Composer install failed');
    }
} else {
    require_once __DIR__ . '/lib/vendor/autoload.php';
    class_alias('Webmozart\Assert\Assert', 'Assert');
}
