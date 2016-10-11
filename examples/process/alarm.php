<?php
swoole_process::signal(SIGALRM, function ()
{
    static $i = 0;
    echo "#{$i}\talarm\n";
    $i++;
    if ($i > 20)
    {
        swoole_process::alarm(-1);
    }
});

swoole_process::alarm(100 * 1000);
