#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

$constant_php = LIBRARY_SRC_DIR . '/core/Constant.php';
if (!file_exists($constant_php)) {
    swoole_error("Unable to find source file [{$constant_php}]");
}

$root_dir = ROOT_DIR;
$file_list = explode("\n", `cd {$root_dir} && git ls-files`);
$file_list = array_filter($file_list, function (string $filename) {
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    return $ext === 'h' || $ext === 'c' || $ext === 'cc';
});

$source_content = '';
foreach ($file_list as $file) {
    $source_content .= file_get_contents("{$root_dir}/{$file}");
}

preg_match_all('/php_swoole_array_get_value\(.+?, "(.+?)", .+?\)/', $source_content, $matches);
$matches = array_unique($matches[1]);
$result = '';
foreach ($matches as $option) {
    $result .= space(4) . sprintf("public const OPTION_%s = '%s';\n\n", strtoupper($option), $option);
}

$constant_php_content = file_get_contents($constant_php);
$constant_php_content = preg_replace(
    '/(\/\* \{\{\{ OPTION \*\/\n)([\s\S]*)(\/\* \}\}\} OPTION \*\/)/',
    '${1}' . $result . space(4) . '${3}',
    $constant_php_content,
    1,
    $replaced
);

if (!$replaced || !file_put_contents($constant_php, $constant_php_content)) {
    swoole_error('Update constant option failed');
}

$server_events = [];
$server_event_file = "{$root_dir}/ext-src/swoole_server.cc";
if (file_exists($server_event_file)) {
    $server_event_content = file_get_contents($server_event_file);
    preg_match_all('/ServerEvent\(SW_SERVER_CB_on(.+?),/', $server_event_content, $server_event);
    $server_events = array_merge($server_events, array_unique($server_event[1]));
}
$server_port_event_file = "{$root_dir}/ext-src/swoole_server_port.cc";
if (file_exists($server_port_event_file)) {
    $server_port_event_content = file_get_contents($server_port_event_file);
    preg_match_all('/server_port_event\(SW_SERVER_CB_on(.+?),/', $server_port_event_content, $server_event);
    $server_events = array_merge($server_events, array_unique($server_event[1]));
}
if (!empty($server_events)) {
    $result = '';
    foreach ($server_events as $event) {
        $result .= space(4) . sprintf("public const EVENT_%s = '%s';\n\n", strtoupper($event), lcfirst($event));
    }

    $constant_php_content = file_get_contents($constant_php);
    $constant_php_content = preg_replace(
        '/(\/\* \{\{\{ EVENT \*\/\n)([\s\S]*)(\/\* \}\}\} EVENT \*\/)/',
        '${1}' . $result . space(4) . '${3}',
        $constant_php_content,
        1,
        $replaced
    );
    if (!$replaced || !file_put_contents($constant_php, $constant_php_content)) {
        swoole_error('Update constant event failed');
    }
}

swoole_success('Constant generator successfully done!');
