<?php
function write_callback($file, $writen)
{
    echo "write $file [$writen]\n";
    //return true: write contine. return false: close the file.
    return true;
}

for ($i = 0; $i < 10; $i++)
{
    swoole_async_write("data.txt", str_repeat('A', 10) . "\n", -1, "write_callback");
}
