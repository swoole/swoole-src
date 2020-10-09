#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

const REGX = '\[([^\]]*)\]';

$server_helper_php = LIBRARY_SRC_DIR . '/core/Server/Helper.php';
if (!file_exists($server_helper_php)) {
    swoole_error("Unable to find source file [{$server_helper_php}]");
}
$php_content = file_get_contents($server_helper_php);

// swoole_server.cc
$source_content = file_get_contents(ROOT_DIR.'/swoole_server.cc');
preg_match_all('/php_swoole_array_get_value\(.+?, "(.+?)", .+?\)/', $source_content, $matches);
$matches = array_unique($matches[1]);
$result = '';
foreach ($matches as $option) {
    $result .= space(8) . sprintf("'%s' => true,\n", strtolower($option), $option);
}

$php_content = preg_replace(
    '/const SERVER_OPTIONS = '.REGX.';/',
    'const SERVER_OPTIONS = ['.PHP_EOL.$result.space(4).'];',
    $php_content,
    1,
    $replaced
);
if (!$replaced) {
    swoole_error("error content [1]");
}

// swoole_server_port.cc
$source_content = file_get_contents(ROOT_DIR.'/swoole_server_port.cc');
preg_match_all('/php_swoole_array_get_value\(.+?, "(.+?)", .+?\)/', $source_content, $matches);
$matches = array_unique($matches[1]);
$result = '';
foreach ($matches as $option) {
    $result .= space(8) . sprintf("'%s' => true,\n", strtolower($option), $option);
}

$php_content = preg_replace(
    '/const PORT_OPTIONS = '.REGX.';/',
    'const PORT_OPTIONS = ['.PHP_EOL.$result.space(4).'];',
    $php_content,
    1,
    $replaced
);
if (!$replaced) {
    swoole_error("error content [2]");
}

// save
if (!file_put_contents($server_helper_php, $php_content)) {
    swoole_error('Update Server\\Helper failed');
}

swoole_success('Update Server\\Helper successfully done!');




