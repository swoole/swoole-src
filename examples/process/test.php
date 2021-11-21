<?php
Swoole\Process::daemon();

while (1)
{
    echo "hello";
    sleep(1);
}
