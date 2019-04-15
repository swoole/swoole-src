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
if (empty(getenv('SWOOLE_DEBUG')) && method_exists('Co', 'set')) {
    Co::set([
        'log_level' => SWOOLE_LOG_INFO,
        'trace_flags' => 0,
    ]);
}

// Components
(function () {
    $autoloader = __DIR__ . '/lib/vendor/autoload.php';
    $composer_dir = __DIR__ . '/lib';
    if (!file_exists($autoloader)) {
        $composer_info = `cd {$composer_dir} && composer install 2>&1`;
        if (!file_exists($autoloader)) {
            throw new RuntimeException('Composer install failed:' . PHP_EOL . $composer_info);
        }
    } elseif (!IS_IN_TRAVIS) {
        `cd {$composer_dir} && composer dump-autoload -o > /dev/null 2>&1`;
    }
    require $autoloader;

    class Assert extends \Webmozart\Assert\Assert
    {
        public static function reportInvalidArgument($message)
        {
            $e = new RuntimeException($message);
            $file = $e->getFile();
            $line = $e->getLine();
            $msg = $e->getMessage();
            $trace = $e->getTraceAsString();
            echo "\nAssert failed: {$msg} in {$file} on line {$line}\nStack trace: \n{$trace}\n";
        }
    }
})();
