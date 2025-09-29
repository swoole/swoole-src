<?php
$arr = typed_array('<int>');

$arr[] = 1;
// $arr[0] += 10;
// assert($arr[0] == 11);
$arr[0] .= "hello world";