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

$coroutineOptions = [
    'exit_condition',
    'deadlock_check_disable_trace',
    'deadlock_check_limit',
    'deadlock_check_depth'
];
$helperOptions = [
    'stats_file',
    'stats_timer_interval',
    'admin_server',
];
$options = array_merge($matches, $coroutineOptions, $helperOptions);
$result = '';
foreach ($options as $option) {
    $result .= space(4) . sprintf("public const OPTION_%s = '%s';\n\n", strtoupper($option), $option);
}

$event_file = [
    "{$root_dir}/ext-src/swoole_server.cc",
    "{$root_dir}/ext-src/swoole_server_port.cc"
];

$server_event_content = '';
foreach ($event_file as $file) {
    $server_event_content .= file_get_contents($file);
}
preg_match_all('/vent\(SW_SERVER_CB_on(.+?),/', $server_event_content, $server_event);
$server_events = array_unique($server_event[1]);

$event_result = '';
foreach ($server_events as $event) {
    if ($event === 'HandShake') {
        $event = 'handshake';
    }
    $event_result .= space(4) . sprintf("public const EVENT_%s = '%s';\n\n", strtoupper(unCamelize($event)), lcfirst($event));
}

$constant_php_content = file_get_contents($constant_php);

$event_pattern = '/(\/\* \{\{\{ EVENT \*\/\n)([\s\S]*)(\/\* \}\}\} EVENT \*\/)/';
$option_pattern = '/(\/\* \{\{\{ OPTION \*\/\n)([\s\S]*)(\/\* \}\}\} OPTION \*\/)/';

function replaceConstantContent($pattern, $result, &$content) {
    $content = preg_replace(
        $pattern,
        '${1}' . $result . space(4) . '${3}',
        $content,
        1,
        $replaced
    );

    return $replaced;
}

$event_replaced = replaceConstantContent($event_pattern, $event_result, $constant_php_content);
$option_replaced = replaceConstantContent($option_pattern, $result, $constant_php_content);

if (!$event_replaced || !$option_replaced || !file_put_contents($constant_php, $constant_php_content)) {
    swoole_error('Update constant failed');
}

swoole_success('Constant generator successfully done!');
