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
    swoole_error('Update Constant failed ');
}

swoole_success('Constant generator successfully done!');
