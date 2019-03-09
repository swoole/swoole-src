#!/usr/bin/env php
<?php
require __DIR__ . '/functions.php';

function get_diff_files(string $dir): array
{
    return scan_dir($dir, function (string $f) {
        return strpos($f, '.diff') !== false;
    });
}

function fix_tests_in_this_dir(string $dir)
{
    $files = scan_dir($dir);
    foreach ($files as $file) {
        if (substr($file, -5, 5) === '.phpt') {
            $dir_name = explode('/', $dir);
            $dir_name = end($dir_name);
            $content = file_get_contents("{$dir}/{$file}");
            preg_match('/--TEST--\n([^:]+?):/', $content, $matches);
            if (!isset($matches[1])) {
                echo "{$dir}/{$file}\n";
            } else {
                if ($dir_name !== $matches[1]) {
                    swoole_ok("Fix title from [{$matches[1]}] to [{$dir_name}] in {$dir}/{$file}");
                    $content = preg_replace(
                        '/(--TEST--\n)([^:]+?)(:)/',
                        '$1' . $dir_name . '$3',
                        $content
                    );
                    file_put_contents("{$dir}/{$file}", $content);
                }
            }
        } elseif (is_dir($file)) {
            fix_tests_in_this_dir("{$dir}/{$file}");
        }
    }
}

$tests_root = __DIR__ . '/../tests';
$tests_dirs = scan_dir($tests_root, function (string $f) {
    return strpos($f, 'swoole_') === 0;
});
array_walk($tests_dirs, function (string $dir) use ($tests_root) {
    fix_tests_in_this_dir("{$tests_root}/{$dir}");
});

swoole_success('Fix test title done!');
