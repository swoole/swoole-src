<?php
Swoole\Process::signal(SIGALRM, function ()
{
    static $i = 0;
    echo "#{$i}\talarm\n";
    $i++;
    if ($i > 20)
    {
        Swoole\Process::alarm(-1);
    }
});

Swoole\Process::alarm(100 * 1000);
