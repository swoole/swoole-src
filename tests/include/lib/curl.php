<?php
function curlGet($url)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    //在http 请求头加入 gzip压缩
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept-Encoding: gzip'));
    //curl返回的结果，采用gzip解压
    curl_setopt($ch, CURLOPT_ENCODING, "gzip");
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
}
