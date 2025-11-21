--TEST--
Bug #7216 (ftp_mkdir returns nothing (2))
--FILE--
<?php
$fn = require 'server.inc';
Co\run(function () use ($fn) {
    $port = $fn();
    // 连接FTP服务器
    $ftp = ftp_connect('127.0.0.1', $port);
    if (!$ftp) die("Couldn't connect to the server");

    // 使用匿名登录
    var_dump(ftp_login($ftp, 'anonymous', 'IEUser@'));

    // 测试ftp_mkdir函数行为
    var_dump(ftp_mkdir($ftp, 'CVS'));

    // 关闭连接
    ftp_close($ftp);
});
--EXPECT--
bool(true)
string(20) "/path/to/ftproot/CVS"
