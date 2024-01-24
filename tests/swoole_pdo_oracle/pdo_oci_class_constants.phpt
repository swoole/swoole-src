--TEST--
swoole_pdo_oracle: PDO OCI specific class constants
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
?>
--FILE--
<?php

$expected = [
    'OCI_ATTR_CLIENT_INFO'        => true,
    'OCI_ATTR_ACTION'             => true,
    'OCI_ATTR_CLIENT_IDENTIFIER'  => true,
    'OCI_ATTR_MODULE'             => true,
    'OCI_ATTR_CALL_TIMEOUT'       => true,
];

$ref = new ReflectionClass('PDO');
$constants = $ref->getConstants();
$values = [];

foreach ($constants as $name => $value) {
    if (substr($name, 0, 8) == 'OCI_ATTR') {
        if (!isset($values[$value])) {
            $values[$value] = [$name];
        } else {
            $values[$value][] = $name;
        }

        if (isset($expected[$name])) {
            unset($expected[$name]);
            unset($constants[$name]);
        }

        } else {
            unset($constants[$name]);
        }
}

if (!empty($constants)) {
    printf("[001] Dumping list of unexpected constants\n");
    var_dump($constants);
}

if (!empty($expected)) {
    printf("[002] Dumping list of missing constants\n");
    var_dump($expected);
}

if (!empty($values)) {
    foreach ($values as $value => $constants) {
        if (count($constants) > 1) {
            printf("[003] Several constants share the same value '%s'\n", $value);
            var_dump($constants);
        }
    }
}

print "done!";
?>
--EXPECT--
done!
