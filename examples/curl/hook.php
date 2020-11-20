<?php
Co::set(['hook_flags' => SWOOLE_HOOK_ALL | SWOOLE_HOOK_NATIVE_CURL, ]);
//Co::set(['hook_flags' => SWOOLE_HOOK_ALL, ]);

Co\run(function () {
    $n = 3;
    while($n--) {
        go('test');
    }
});

function test() {
    echo "curl init\n";
    $ch = curl_init();
//    $url = 'https://www.baidu.com/';
    $url = "http://127.0.0.1:9801/";

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
        //var_dump($ch, $strHeader);
        return strlen($strHeader);
    });

    $output = curl_exec($ch);
    var_dump($output);
    var_dump(strlen($output));
    if ($output === false) {
        echo "CURL Error:" . curl_error($ch);
    }
//    var_dump($output);
    curl_close($ch);
}
