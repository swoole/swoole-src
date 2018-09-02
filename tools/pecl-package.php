<?php
// clear
$this_dir = __DIR__;
$tests_dir = __DIR__ . '/../tests/';
`cd {$tests_dir} && ./clean && cd {$this_dir}`;

$root_dir = __DIR__ . '/../';
$file_list_raw = `cd {$root_dir} && git ls-files`;
$file_list_raw = explode("\n", $file_list_raw);
$file_list = [];
foreach ($file_list_raw as $file) {
    if (empty($file)) {
        continue;
    }
    if (is_dir($root_dir . $file)) {
        continue;
    }
    if ($file === 'package.xml') {
        continue;
    }
    $ext = pathinfo($file, PATHINFO_EXTENSION);
    $role = 'src';
    switch ($ext) {
        case 'phpt':
            $role = 'test';
            break;
        case 'md':
        case 'txt':
            $role = 'doc';
            break;
        case '':
            if (substr(file_get_contents($root_dir . $file), 0, 2) !== '#!') {
                $role = 'doc';
            }
            break;
    }
    $file_list[] = "<file role=\"{$role}\" name=\"{$file}\" />\n";
}

$content = file_get_contents(__DIR__ . '/../package.xml');
if (!preg_match('/([ ]*)\<dir[ ]name=\"\/\">/', $content, $matches)) {
    exit('match dir tag failed!');
}
$space = strlen($matches[1]);
$space += 4;
$space = str_repeat(' ', $space);
$dir_tag = '<dir name="/">' . "\n";
$content = preg_replace('/(\<dir[ ]name=\"\/\">)([\s\S]*?)(\n[ ]*?\<\/dir>)/', '$1$3', $content, 1, $success);
if (!$success) {
    exit('replace old content failed!');
}
$content = str_replace($dir_tag, $dir_tag . $space . implode("{$space}", $file_list), $content, $success);
if (!$success) {
    exit('replace new content failed!');
}
if (!file_put_contents(__DIR__ . '/../package.xml', $content)) {
    exit('output package successful!');
}
exit('package successful!');