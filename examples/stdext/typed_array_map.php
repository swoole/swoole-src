<?php
$list = typed_array('<string, int>');

$list["hello"] = 123;
$list[] = 345;
$list["hello"] = 'hello';
