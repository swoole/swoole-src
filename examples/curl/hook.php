<?php
Co::set(['hook_flags' => SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL_NATIVE, ]);

Co\run(function () {
    $n = 3;
    while($n--) {
        go('test');
    }
});

function test() {
    echo "curl init\n";
    $ch = curl_init();
    var_dump($ch);
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:9801/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, $strHeader) {
        var_dump($ch, $strHeader);
        return strlen($strHeader);
    });

    $output = curl_exec($ch);
    var_dump($output);
    if ($output === false) {
        echo "CURL Error:" . curl_error($ch);
    }
    echo $output;
    curl_close($ch);
}