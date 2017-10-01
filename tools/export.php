<?php
if ($argc == 1) {
    die("Usage: php export.php [class_name]\n");
}
ReflectionClass::export($argv[1]);
