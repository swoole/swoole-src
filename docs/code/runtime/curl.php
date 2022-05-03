<?php
/**
 * User: lufei
 * Date: 2020/8/5
 * Email: lufei@swoole.com
 */

Co::set(['hook_flags' => SWOOLE_HOOK_CURL]);

$s = microtime(true);
Co\run(function () {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://www.xinhuanet.com/");
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);
    curl_close($ch);
//    var_dump($result);
});
echo 'use ' . (microtime(true) - $s) . ' s';

