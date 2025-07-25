<?php
$str = "hello world";
var_dump($str->toUpper());

var_dump($str->split(" ")->search("world"));
var_dump($str->length());
var_dump("test"->length());

var_dump($str->indexOf("world"));
var_dump($str->substr(1, 4));

var_dump($str->startsWith("hello"));
var_dump($str->endsWith("world"));
var_dump($str->endsWith(".php"));

var_dump($str->md5(), $str->sha1(), $str->crc32());