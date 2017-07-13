<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

//swoole_function swoole_async_readfile($filename, $callback) {}


function read_dev_zero()
{
    $context = file_get_contents("/dev/zero", null, null, null, 8192);
    assert(strlen($context) === 8192);

    // TODO WARNING	zif_swoole_async_readfile: file is empty.
    swoole_async_readfile("/dev/zero", function ($filename, $content) {
        echo "file: $filename\ncontent-length: " . strlen($content) . "\nContent: $content\n";
        if (empty($content)) {
            echo "file is end.\n";
            return false;
        } else {
            return true;
        }
    });
}

function read_dev_null()
{
    $context = file_get_contents("/dev/null", null, null, null, 8192);
    assert(strlen($context) === 0);

    // TODO WARNING	zif_swoole_async_readfile: file is empty.
    swoole_async_readfile("/dev/null", function ($filename, $content) {
        echo "file: $filename\ncontent-length: " . strlen($content) . "\nContent: $content\n";
        if (empty($content)) {
            echo "file is end.\n";
            return false;
        } else {
            return true;
        }
    });
}


function read_normal_file()
{
    $context = file_get_contents(__FILE__, null, null, null, 8192);
    $len = strlen($context);

    swoole_async_readfile(__FILE__, function ($filename, $content) use($len) {
        echo "read callback\n";
        if (empty($content)) {
            echo "file is end.\n";
            return false;
        } else {
            return true;
        }
    });
}

read_dev_zero();
read_dev_null();
read_normal_file();

// todo read 大文件