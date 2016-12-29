<?php
$fp = fopen (__DIR__. '/test.html', 'w+');
$ch = curl_init("http://127.0.0.1/index.php");
curl_setopt($ch, CURLOPT_TIMEOUT, 50);
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
// write curl response to file
curl_setopt($ch, CURLOPT_FILE, $fp); 
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
// get curl response
curl_exec($ch); 
curl_close($ch);
fclose($fp);
