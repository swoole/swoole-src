#!/usr/bin/env php
<?php
define('BASE_DIR', dirname(__DIR__));
if (empty($argv[1]))
{
    $DIR = BASE_DIR . '/tests';
}
else
{
    $DIR = BASE_DIR . '/' . $argv[1];
}

$role = empty($argv[2]) ? 'test' : 'src';
$cmd = empty($argv[3]) ? 'list' : 'check';

$_files = [];
search($DIR, $_files);

foreach ($_files as $f)
{
    $filename = str_replace($DIR . '/', '', $f);
    if ($cmd == 'list')
    {
        echo '<file name="' . $filename . '" role="' . $role . '" />' . "\n";
    }
    elseif ($cmd == 'check')
    {
        if (!inPackage($filename))
        {
            echo "$filename\n";
        }
    }
}

function search($path, &$_files)
{
    $dirs = _scandir($path);
    foreach ($dirs as $d)
    {
        $_path = $path . '/' . $d;
        if (!is_dir($_path))
        {
            $_files[] = $_path;
            continue;
        }
        else
        {
            search($_path, $_files);
        }
    }
}

function _scandir($dir)
{
    $list = scandir($dir);
    return array_filter($list, function ($f)
    {
        return $f[0] !== '.';
    });
}

function inPackage($file)
{
    static $content = null;
    if (!$content)
    {
        $content = file_get_contents(BASE_DIR . '/package.xml');
    }
    if (strpos($content, $file) === false)
    {
        return false;
    }
    else
    {
        return true;
    }
}
