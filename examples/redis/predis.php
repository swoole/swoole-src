<?php
$redis = new redis;
$redis->connect('127.0.0.1', 6379);
var_dump($redis->ping());
