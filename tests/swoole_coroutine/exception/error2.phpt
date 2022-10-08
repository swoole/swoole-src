--TEST--
swoole_coroutine/exception: zend_error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    try {
         echo "start\n";
        $wsdl = 'http://1.1.1.1/soap.cls?wsdl';
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
--EXPECT--
start
SOAP-ERROR: Parsing WSDL: Couldn't load from 'http://1.1.1.1/soap.cls?wsdl' : Premature end of data in tag html line 1
end
