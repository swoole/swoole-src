<?php

Swoole\Runtime::enableCoroutine();

go(function () {

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://www.gov.cn/xinwen/index.htm");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    $output = curl_exec($ch);
    if ($output === FALSE) {
        echo "CURL Error:" . curl_error($ch);
    }
    curl_close($ch);
    echo strlen($output) . "bytes\n";
});

swoole_event_wait();