<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

// TODO 线上版本 512k coredump
//$chunk = 1024 * 512;
//parallel_read_copy($chunk);



//$chunk = 1024 * 1024;
//parallel_read_copy($chunk);

//$chunk = 1024 * 1024 - 1;
//parallel_read_copy($chunk);

//serial_read_copy();


// DOC
// 读全部文件chunk = -1 或者 不传递
// 不需要chunk参数，强制性一次读取1M数据
// swoole_function swoole_async_read($file, callable $cb, $chunk, $offset) {}


// 新接口取消readfile与writefile

function gen_rand_file($file, $m = 10)
{
    // !! linux 的bs不支持m作为单位 !!!
    $bs = 1024 * 1024;
    `dd if=/dev/urandom of=$file bs=$bs count=$m >/dev/null 2>&1`;
    // 可能会失败
    // return filesize($file);
    return $m * 1024 * 1024;
}


// 验证复制完整性并清理文件
function valid_clean($from, $to)
{
//    echo "copy finished\n";
//    echo `ls -alh | grep $from`;
    $diff = `diff $from $to`; // valid
    if ($diff) {
         echo $diff;
        echo "FAIL\n";
    } else {
        echo "SUCCESS\n";
    }
    @unlink($from);
    @unlink($to);
}


// 重构后swoole版本api
function serial_read_copy($size_m = 10)
{
    $start = microtime(true);

    $chunk = 1024 * 1024;

    $offset = 0;
    $file = "bigfile";
    $origin_size = gen_rand_file($file, $size_m);

    $n = (int)ceil($origin_size / $chunk);
    swoole_async_set([ "thread_num" => $n,]);

    $i = 0;
    swoole_async_read($file, function($filename, $content) use($file, &$offset, &$n, &$i, $start) {

        $read_size = strlen($content);
        //echo "<$i> read [offset=$offset, len=$read_size]\n";

        $continue = $read_size !== 0;
        if ($continue) {
            swoole_async_write("$file.copy", $content, $offset, function($write_file, $write_size) use($file, $offset, $read_size, &$n, $i, $start) {
                $n--;

                assert($read_size === $write_size); // 断言分块全部写入
                //echo "<$i> write [offset=$offset, len=$write_size]\n";

                if ($n === 0) {
                    //echo "cost: ", microtime(true) - $start, "\n";
                    valid_clean($file, $write_file);
                }
            });
        }

        $offset += $read_size;
        $i++;

        return $continue;

    }, $chunk);
}


function parallel_read_copy($chunk, $size_m = 10)
{
    $start = microtime(true);

    $offset = 0;
    $file = "bigfile";
    //生成一个10M大小的文件
    $origin_size = gen_rand_file($file, $size_m);
    $n = (int)ceil($origin_size / $chunk);
    //设置线程数
    swoole_async_set([ "thread_num" => $n,]);

    for ($i = 0; $i < $n; $i++) {
        $offset = $i * $chunk;

        swoole_async_read($file, function($filename, $content) use($file, $offset, $i, &$n, $start) {

            $read_size = strlen($content);
//            echo "<$i> read [offset=$offset, len=$read_size]\n";

            swoole_async_write("$file.copy", $content, $offset, function($write_file, $write_size) use($file, $offset, $read_size, &$n, $i, $start) {
                $n--;

                assert($read_size === $write_size); // 断言分块全部写入
//                echo "<$i> write [offset=$offset, len=$write_size]\n";

                if ($n === 0) {
//                    echo "cost: ", microtime(true) - $start, "\n";
                    valid_clean($file, $write_file);
                }
            });

            // !!! 只读取单独chunk，停止继续读
            return false;
        }, $chunk, $offset);
    }
}



// 旧的swoole版本api 使用
function serial_copy_old($chunk)
{
    $offset = 0;
    $file = "bigfile";
    $origin_size = gen_rand_file($file);

    $n = (int)ceil($origin_size / $chunk);
    swoole_async_set([ "thread_num" => $n,]);

    $i = 0;
    swoole_async_read($file, function($filename, $content) use($file, &$offset, &$n, &$i) {

        $read_size = strlen($content);
        echo "<$i> read [offset=$offset, len=$read_size]\n";

        $continue = $read_size !== 0;
        if ($continue) {
            swoole_async_write("$file.copy", $content, $offset, function($write_file, $write_size) use($file, $offset, $read_size, &$n, $i) {
                $n--;

                assert($read_size === $write_size); // 断言分块全部写入
                echo "<$i> write [offset=$offset, len=$write_size]\n";

                if ($n === 0) {
                    valid_clean($file, $write_file);
                }
            });
        }

        $offset += $read_size;
        $i++;
        return $continue;

    }, $chunk);
}