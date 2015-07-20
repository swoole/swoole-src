<?php
swoole_process::daemon();

while (1)
{
    echo "hello";
    sleep(1);
}