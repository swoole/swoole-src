<?php
var_dump([
    'version' => swoole_version(),
    'cpu_num' => swoole_cpu_num(),
    'local_mac' => swoole_get_local_mac(),
    'local_ip' => swoole_get_local_ip()
]);
