<?php
require_once __DIR__ . "/../../../include/bootstrap.php";


//swoole_function swoole_async_read($filename, $callback, $chunk_size = null, $offset = null) {}
//swoole_function swoole_async_write($filename, $content, $offset = null, $callback = null) {}
//swoole_function swoole_async_readfile($filename, $callback) {}
//swoole_function swoole_async_writefile($filename, $content, $callback = null) {}

// WARNING	zif_swoole_async_readfile: file_size[size=1073741824|max_size=4194304] is too big. Please use swoole_async_read.

function rw_small_file() {
    $file = __DIR__ . "/small_zero";

    @unlink($file);
    @unlink("$file.copy");
    $len = 1024 * 1024 * 4; // 4M
    $put_len = file_put_contents($file, str_repeat("\0", $len), FILE_APPEND);
    assert($put_len === $len);

    swoole_async_readfile($file, function($filename, $content) use($file) {
        swoole_async_writefile("$file.copy", $content, function($write_file) use($file) {
            // echo "copy small file finish\n";
            // echo `ls -alh | grep zero`;
            assert(filesize($write_file) === filesize($file));
            unlink($write_file);
            unlink($file);
            echo "SUCCESS";
        });
    });
}

function rw_big_file() {
    $file = __DIR__ . "/big_zero";

    @unlink($file);
    @unlink("$file.copy");
    // 生成1G文件
    for($i = 0; $i < 1024; $i++) {
        $len = 1024 * 1024;
        $put_len = file_put_contents($file, str_repeat("\0", $len), FILE_APPEND);
        assert($put_len === $len);
    }

    // chunk = 1M copy
    $i = 0;
    swoole_async_read($file, function($filename, $content) use($file, &$i) {
        // echo "read " . strlen($content) . " size\n";
        $continue = true;
        if (empty($content)) {
            $continue = false;
        }

        $offset = $i * 1024 * 1024;
        // echo "write offset $offset\n";
        swoole_async_write("$file.copy", $content, $offset, function($write_file, $len) use($file, &$i, $continue) {
            // echo "write $len size\n";
            $i++;
            if ($continue === false) {
                // echo "copy finished\n";
                // echo `ls -alh | grep zero`;
                sleep(1);
                assert(filesize($write_file) === filesize($file));
                unlink($file);
                unlink($write_file);
                echo "SUCCESS";
            }
        });

        return $continue;

    }, 1024 * 1024);
}


rw_small_file();
rw_big_file();