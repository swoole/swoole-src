<?php

define('ROOT_PATH', dirname(__DIR__));

require_once ROOT_PATH . '/tests/include/bootstrap.php';

$core_header_files = _array(glob(ROOT_PATH . '/include/*.h'));
echo "Number of core header files: " . $core_header_files->count() . PHP_EOL;

$ext_header_files = _array(glob(ROOT_PATH . '/ext-src/php_*.h'));
echo "Number of php-ext header files: " . $ext_header_files->count() . PHP_EOL;

$core_source_files = _array(scan_dir_recursive(ROOT_PATH . '/src'))->filter(function ($value) {
    return pathinfo($value, PATHINFO_EXTENSION) == 'cc';
});
echo "Number of core source files: " . $core_source_files->count() . PHP_EOL;

$core_source_files = _array(scan_dir(ROOT_PATH . '/ext-src'))->filter(function ($value) {
    return pathinfo($value, PATHINFO_EXTENSION) == 'cc';
});
echo "Number of php-ext source files: " . $core_source_files->count() . PHP_EOL;