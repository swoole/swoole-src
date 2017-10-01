<?php
require_once __DIR__ . "/../../../include/bootstrap.php";

//swoole_function swoole_async_write($filename, $content, $offset = null, $callback = null) {}
//callback: return true: write contine. return false: close the file.

function write_dev_zero()
{
    $data = str_repeat("\0", 8192);
    $len = file_put_contents("/dev/zero", $data);
    assert($len === 8192);

    for ($i = 0; $i < 100; $i++) {
        swoole_async_write("/dev/zero", $data, -1, function ($file, $len) {
            echo "write /dev/zero $len size\n";
            return true;
        });
    }
}

function write_dev_null()
{
    $data = str_repeat("\0", 8192);
    $len = file_put_contents("/dev/null", $data);
    assert($len === 8192);

    for ($i = 0; $i < 100; $i++) {
        swoole_async_write("/dev/null", $data, -1, function ($file, $len) {
            echo "write /dev/null $len size\n";
            return true;
        });
    }
}


function write_normal_file()
{
    $file = __DIR__ . "/zero";

    $data = str_repeat("\0", 8192);
    $len = file_put_contents($file, $data);
    assert($len === 8192);
    unlink($file);

    /** @noinspection PhpUnusedLocalVariableInspection
     * @param int $dep
     */
    $recursiveWrite = function($dep = 0) use($data, &$recursiveWrite, $file) {
        swoole_async_write($file, $data, -1, function ($file, $len) use(&$recursiveWrite, $dep) {
            if ($dep > 100) {
                unlink($file);
                return false;
            }

            echo "write $file $len size\n";
            $recursiveWrite(++$dep);
            return true;
        });
    };

    $recursiveWrite();

}

write_dev_zero();
write_dev_null();
write_normal_file();
