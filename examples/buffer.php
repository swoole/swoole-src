<?php
$buffer = new swoole_buffer;
$buffer->append(str_repeat("A", 1024));
var_dump($buffer);
echo $buffer->substr(0, 5)."\n";
