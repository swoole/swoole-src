<?php
function curlGet($url, $gzip = true)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    if ($gzip)
    {
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept-Encoding: gzip'));
        curl_setopt($ch, CURLOPT_ENCODING, "gzip");
    }
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
}
