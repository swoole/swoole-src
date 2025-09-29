<?php
$array = [1, 2, 3, 4, 5];

$arr = $array->slice(1, 2);
var_dump($arr);

$array1 = ['a' => 1, 'b' => 2, 'c' => 3, 'd' => 4, 'e' => 5];
$array2 = [6, 7, 8, 9, 10, 11, 12];

var_dump($array2->count());

// var_dump($array2->all(function ($value) {
//     return $value > 10;
// }));

$input_array = array("FirSt" => 1, "SecOnd" => 4);
print_r($input_array->changeKeyCase(CASE_UPPER));

$array4 = array(0 => 'blue', 1 => 'red', 2 => 'green', 3 => 'red');
$key = $array4->search('green');
var_dump($key);

echo "==================================[contains]===================================\n";
$os = array("Mac", "Windows", "Linux");
var_dump($os->contains("Windows"));
var_dump($os->contains("Unix"));

echo "==================================[isList]===================================\n";
var_dump($array1->isList());
var_dump($array2->isList());

var_dump($array1->keys());
var_dump($array2->values());

echo "==================================[join]===================================\n";
var_dump(['a', 'b', 'c']->join(','));

echo "==================================[method not exists]===================================\n";
try {
    $array->notExists();
} catch (throwable $e) {
    echo "Caught exception: ",  $e->getMessage(), "\n";
}

function odd($var)
{
    // returns whether the input integer is odd
    return $var & 1;
}

function even($var)
{
    // returns whether the input integer is even
    return !($var & 1);
}

echo "Odd :\n";
print_r($array1->filter("odd"));

echo "Even:\n";
print_r($array2->filter("even"));


echo "==================================[array_map]===================================\n";

$a = [1, 2, 3, 4, 5];
$b = $a->map(function ($n) {
    return ($n * $n * $n);
});
var_dump($b);

echo "==================================[array_key_exists]===================================\n";
$searchArray = ['first' => null, 'second' => 4];

var_dump(isset($searchArray['first']));
var_dump($searchArray->keyExists('first'));
