#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

const REGX = '\[([^\]]*)\]';

$server_helper_php = LIBRARY_SRC_DIR . '/core/Server/Helper.php';
if (!file_exists($server_helper_php)) {
    swoole_error("Unable to find source file [{$server_helper_php}]");
}
$php_content = file_get_contents($server_helper_php);

function _replace_options($file, &$php_content, $name) {
    $source_content = file_get_contents($file);
    preg_match_all('/php_swoole_array_get_value\(.+?, "(.+?)", .+?\)/', $source_content, $matches);
    $matches = array_unique($matches[1]);
    $result = '';
    foreach ($matches as $option) {
        $result .= space(8) . sprintf("'%s' => true,\n", strtolower($option), $option);
    }

    $php_content = preg_replace(
        '/const '.$name.' = '.REGX.';/',
        'const '.$name.' = ['.PHP_EOL.$result.space(4).'];',
        $php_content,
        1,
        $replaced
    );
    if (!$replaced) {
        swoole_error("error content [$name]");
    }
}

_replace_options(ROOT_DIR.'/ext-src/php_swoole.cc', $php_content, 'GLOBAL_OPTIONS');
_replace_options(ROOT_DIR.'/ext-src/swoole_server.cc', $php_content, 'SERVER_OPTIONS');
_replace_options(ROOT_DIR.'/ext-src/swoole_server_port.cc', $php_content, 'PORT_OPTIONS');
_replace_options(ROOT_DIR.'/ext-src/swoole_async_coro.cc', $php_content, 'AIO_OPTIONS');
_replace_options(ROOT_DIR.'/ext-src/swoole_coroutine_scheduler.cc', $php_content, 'COROUTINE_OPTIONS');

// save
if (!file_put_contents($server_helper_php, $php_content)) {
    swoole_error('Update Server\\Helper failed');
}

swoole_success('Update Server\\Helper successfully done!');




