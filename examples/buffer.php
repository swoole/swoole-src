<?php
$buffer = new swoole_buffer;
$buffer->append(str_repeat("A", 10));
$buffer->append(str_repeat("B", 20));
$buffer->append(str_repeat("C", 30));

var_dump($buffer);
echo $buffer->substr(0, 10, true)."\n";
echo $buffer->substr(0, 20, true)."\n";
echo $buffer->substr(0, 30)."\n";
$buffer->clear();

echo $buffer->substr(0, 10, true)."\n";
var_dump($buffer);
sleep(1);
