<?php
# @remicollet
# https://github.com/swoole/swoole-src/commit/ffff7ce074accf7b47768fca6eb238627d7a6b93#r30410846
# role="src" => not installed, so files only used for the build
# role="doc" => in $(pecl config-get doc_dir), which is /usr/share/doc/pecl/swoole on RPM distro (LICENSE being an exception, manually moved to /usr/share/licenses)
# role="test" => in $(pecl config-get test_dir), which is /usr/share/tests/pecl/swoole on RPM distro

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
    if ($file === 'package.xml' || substr($file, 0, 1) === '.') {
        continue;
    }
    if (strpos($file, 'tests') === 0) {
        $role = 'test';
    } elseif (strpos($file, 'examples') === 0) {
        $role = 'doc';
    } else {
        $ext = pathinfo($file, PATHINFO_EXTENSION);
        $role = 'src';
        switch ($ext) {
            case 'phpt':
                $role = 'test';
                break;
            case 'md':
                $role = 'doc';
                break;
            case '':
                if (substr(file_get_contents($root_dir . $file), 0, 2) !== '#!') {
                    $role = 'doc';
                }
                break;
        }
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
echo $result = trim(`cd {$root_dir} && pecl package-validate`);
exit(strpos($result, '0 error') === false);