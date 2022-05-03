#!/usr/bin/env php
<?php
/**
 * User: lufei
 * Date: 2021/6/7
 * Email: lufei@swoole.com
 */

$ref = new ReflectionExtension('swoole');
$con = $ref->getConstants();

$num = 5;
foreach ($con as $key => $v) {
    $is_error = strstr($key, 'SWOOLE_ERROR_');
    if ($is_error) {
        $tmp_num = intval($v / 100);
        if ($tmp_num > $num) {
            echo "|-||||" . PHP_EOL;
            $num = $tmp_num;
        }
        echo "| {$key} | {$v} | " . swoole_strerror($v, 9) . " |" . PHP_EOL;
    }
}
