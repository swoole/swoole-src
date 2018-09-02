<?php
go(function () {
    $a = "hello";
    $b = "world";
    $str = $a.str_repeat(' ', 1).$b."\n";
    echo $str;
	exit($str);
});
