<?php

$fruits = array("lemon", "orange", "banana", "apple");
echo "Before sorting:\n";
foreach ($fruits as $key => $val) {
    echo "fruits[" . $key . "] = " . $val . "\n";
}

$b = &$fruits;
$b->sort(SORT_NATURAL | SORT_FLAG_CASE);

echo "After sorting:\n";
foreach ($fruits as $key => $val) {
    echo "fruits[" . $key . "] = " . $val . "\n";
}

$stack = array("orange", "banana", "apple", "raspberry");

$ref = &$stack;
$fruit = $ref->shift();
var_dump($stack);

$ref->unshift("kiwi");
var_dump($stack);
