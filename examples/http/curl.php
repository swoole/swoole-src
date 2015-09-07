<?php
// 创建一个新cURL资源
$ch = curl_init();
// 设置URL和相应的选项
curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:9501");
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_POST, 1);//设置为POST方式
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));

$post_data = array('test' => str_repeat('a', 80));

if (function_exists("curl_file_create"))
{
    $cfile = curl_file_create(__DIR__ . '/../test.jpg');
    $post_data['file'] = $cfile;
}
else
{
    $post_data['file'] = '@' . __DIR__ . '/../test.jpg';
}

curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);  //POST数据
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
// 抓取URL并把它传递给浏览器
$res =  curl_exec($ch);
var_dump($res);
// 关闭cURL资源，并且释放系统资源
curl_close($ch);
