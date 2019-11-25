#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

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
            $requirement_level = (function () use ($root, $file) {
                for ($l = 0; $l < 8; $l++) {
                    $file = dirname($file);
                    if ($file === $root) {
                        return $l;
                    }
                }
                return -1;
            })();
            if ($requirement_level < 0) {
                swoole_error("Failed to get requirement level of file {$file}");
            }
            $content = file_get_contents($file);
            $changed = false;
            // empty lines
            $_content = trim($content) . "\n";
            if ($content !== $_content) {
                swoole_ok("Format empty lines in {$file}");
                $content = $_content;
                $changed = true;
            }
            // white lines
            $content = preg_replace('/\n{2,}--/', "\n--", $content, -1, $count);
            if ($count) {
                swoole_ok("Removed white lines in {$file}");
                $changed = true;
            }
            // no file
            if (strpos($content, '--FILE--') === false) {
                swoole_warn("Can not find --FILE-- in {$file}");
            }
            // no bootstrap
            if (strpos($content, 'include/bootstrap.php') === false) {
                swoole_warn("Can not find bootstrap in {$file}");
            }
            // unused skipif
            if (strpos($content, 'include/skipif.inc') === false) {
                $skip_requirement_outer = str_repeat('/..', $requirement_level);
                $skip_requirement = "<?php require __DIR__ . '{$skip_requirement_outer}/include/skipif.inc'; ?>\n";
                if (strpos($content, '--SKIPIF--') !== false) {
                    $content = preg_replace("/--SKIPIF--\n/", "\${0}{$skip_requirement}", $content, 1, $count);
                } else {
                    $content = preg_replace("/--FILE--/", "--SKIPIF--\n{$skip_requirement}\${0}", $content, 1, $count);
                }
                if (!$count) {
                    swoole_error("Add skipif.inc failed in {$file}");
                } else {
                    swoole_ok("Add skipif.inc to the script in file {$file}");
                }
                $changed = true;
            }
            // title
            preg_match('/--TEST--\n([^\n]+)/', $content, $matches);
            $current_title = $matches[1] ?? '';
            if (!$current_title) {
                swoole_warn("Can not find title in {$file}");
                goto _finished;
            }
            $current_title_array = explode(':', $current_title);
            $current_title_dir_name = $current_title_array[0];
            if (count($current_title_array) < 2) {
                $content = preg_replace(
                    '/--TEST--\n/',
                    '$0' . $title_dir_name . ': ',
                    $content,
                    1, $count
                );
                _check_title:
                if (!$count) {
                    swoole_error("Replace title failed in {$file}");
                } else {
                    swoole_ok("Fix title dir name from [{$current_title_dir_name}] to [{$title_dir_name}] in {$file}");
                }
                $changed = true;
            } elseif ($current_title_dir_name !== $title_dir_name) {
                $content = preg_replace(
                    '/(--TEST--\n)(?:.+)(:)/',
                    '$1' . $title_dir_name . '$2',
                    $content,
                    1, $count
                );
                goto _check_title;
            }
            _finished:
            if ($changed) {
                file_put_contents($file, $content);
            }
        } elseif (is_dir($file)) {
            fix_tests_in_this_dir($file, $root);
        }
    }
}

$root = realpath(ROOT_DIR . '/tests');
$dirs = scan_dir($root, function (string $file) {
    return strpos(pathinfo($file, PATHINFO_FILENAME), 'swoole_') === 0;
});
foreach ($dirs as $dir) {
    fix_tests_in_this_dir($dir, $root);
}
swoole_success('PHPT-Fixer done');
