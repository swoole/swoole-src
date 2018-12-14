#!/usr/bin/env php
<?php
if ($argc == 1) {
    exit("Usage: php export.php [class_name]\n");
}
ReflectionClass::export($argv[1]);
