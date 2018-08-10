#!/usr/bin/env php
<?php
define('BASE_DIR', dirname(__DIR__));

$this_dir = __DIR__;
$tests_dir = __DIR__ . '/../tests/';
`cd {$tests_dir} && ./clean && cd {$this_dir}`;

function search($path, &$_files)
{
    $dirs = _scandir($path);
    foreach ($dirs as $d) {
        $_path = $path . '/' . $d;
        if (!is_dir($_path)) {
            $_files[] = $_path;
            continue;
        } else {
            search($_path, $_files);
        }
    }
}

function _scandir($dir)
{
    $list = scandir($dir);
    return array_filter($list, function ($f) {
        return $f[0] !== '.';
    });
}

function inPackage($file)
{
    static $content = null;
    if (!$content) {
        $content = file_get_contents(BASE_DIR . '/package.xml');
    }
    if (strpos($content, $file) === false) {
        return false;
    } else {
        return true;
    }
}

if (empty($argv[1])) {
    $DIR = BASE_DIR . '/tests';
} else {
    $DIR = BASE_DIR . '/' . $argv[1];
}

$role = empty($argv[2]) ? 'test' : 'src';
$cmd = empty($argv[3]) ? 'list' : 'check';

$_files = [];
search($DIR, $_files);

ob_start();
foreach ($_files as $f) {
    $filename = str_replace($DIR . '/', '', $f);
    if ($cmd == 'list') {
        echo str_repeat(' ', 16);
        echo '<file name="' . $filename . '" role="' . $role . '" />' . "\n";
    } elseif ($cmd == 'check') {
        if (!inPackage($filename)) {
            echo "$filename\n";
        }
    }
}

$package_filename = __DIR__ . '/../package.xml';
$package_content = file_get_contents($package_filename);
$package_content = preg_replace(
    '/([ ]{12}<dir name="tests">\n)([\s\S]+?)([ ]{12}<\/dir>)/',
    '$1' . ob_get_contents() . '$3',
    $package_content
);
file_put_contents($package_filename, $package_content);
