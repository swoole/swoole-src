<?php
use Swoole\Coroutine as co;

$fp = fopen(__DIR__ . "/defer_client.php", "r");

co::create(function () use ($fp)
{
    fseek($fp, 256);
    $r =  co::fread($fp);
    var_dump($r);
});