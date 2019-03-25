#!/usr/bin/env php
<?php
require __DIR__ . '/functions.php';

function fix_tests_in_this_dir(string $dir, string $root = '')
{
    $files = scan_dir($dir);
    if (empty($root)) {
        $title_dir_name = explode('/', $dir);
        $title_dir_name = end($title_dir_name);
    } else {
        $title_dir_name = trim(str_replace(realpath($root), '', realpath($dir)), '/');
    }
    foreach ($files as $file) {
        if (pathinfo($file, PATHINFO_EXTENSION) === 'phpt') {
            $content = file_get_contents($file);
            $changed = false;
            // no bootstrap
            if (strpos($content, 'include/bootstrap.php') === false) {
                swoole_warn("Can not find bootstrap in {$file}");
            }
            // white lines
            $content = preg_replace('/\n{2,}--/', "\n--", $content, -1, $count);
            if ($count) {
                swoole_ok("Removed white lines in {$file}");
                $changed = true;
            }
            // unused skipif
            if (strpos($content, '--SKIPIF--') !== false && strpos($content, 'include/skipif.inc') === false) {
                swoole_warn("Can not find skipif.inc but SKIPIF tag exists in {$file}");
                $content = preg_replace('/--SKIPIF--[^-]/', '', $content, 1, $count);
                if (!$count) {
                    swoole_error("Remove SKIPIF failed in {$file}");
                } else {
                    swoole_ok("Removed unused SKIPIF in {$file}");
                    $changed = true;
                }
            }
            // title
            preg_match('/--TEST--\n(.+):/', $content, $matches);
            if (!isset($matches[1])) {
                swoole_warn("Can not find title in {$file}");
                continue;
            }
            if ($title_dir_name !== $matches[1]) {
                $content = preg_replace(
                    '/(--TEST--\n)(?:.+)(:)/',
                    '$1' . $title_dir_name . '$2',
                    $content,
                    1, $count
                );
                if (!$count) {
                    swoole_error("Replace title failed in {$file}");
                } else {
                    swoole_ok("Fix title from [{$matches[1]}] to [{$title_dir_name}] in {$file}");
                    $changed = true;
                }
            }
            if ($changed) {
                file_put_contents($file, $content);
            }
        } elseif (is_dir($file)) {
            fix_tests_in_this_dir($file, $root);
        }
    }
}

$root = __DIR__ . '/../tests';
$dirs = scan_dir($root, function (string $file) {
    return strpos(pathinfo($file, PATHINFO_FILENAME), 'swoole_') === 0;
});
foreach ($dirs as $dir) {
    fix_tests_in_this_dir($dir, $root);
}
swoole_success('PHPT-Fixer done');
