--TEST--
swoole_coroutine/exception: zend_error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('soap');?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    try {
        echo "start\n";
        $wsdl = 'http://127.0.0.1:59999/soap.cls?wsdl';
        $option = array_merge([
            'connection_timeout' => 1,
            'location' => $wsdl,
            'features' => 1,
            'exceptions' => true,
        ], []);
        $client = new \SoapClient($wsdl, $option);
    } catch (\Exception $e) {
        echo $e->getMessage();
    }
});
echo "end\n";

?>
--EXPECTF--
start
SOAP-ERROR: Parsing WSDL: Couldn't load from '%s' : failed to load external entity "%s"
end
