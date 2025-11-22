--TEST--
ftp_connect - return FALSE if connection fails and Waning is generated
--FILE--
<?php
Co\run(function () {
    $ftp = ftp_connect('dummy-host-name', 21, 5);
    var_dump($ftp);
});
?>
--EXPECTF--
Warning: ftp_connect(): getaddrinfo for 'dummy-host-name' failed, error: %s in %s on line %d
bool(false)
