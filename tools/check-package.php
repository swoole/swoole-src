#!/usr/bin/env php
<?php
define('TEST_DIR', dirname(__DIR__).'/tests');
//unit test files
$_files = [];
search(TEST_DIR, $_files);

foreach($_files as $f)
{
    echo  '<file name="'.str_replace(TEST_DIR.'/', '', $f).'" role="test" />'."\n";
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
        $content = file_get_contents(__DIR__ . '/package.xml');
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
