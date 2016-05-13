<?php
swoole_async_writefile(__DIR__.'/data2.txt', str_repeat('A', 1024)."\n");
