<?php
require __DIR__ . '/../vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
VersaModel::setORM($orm);

$m = VersaModel::dispense('items');
$m->sku = 'X1';
$m->qty = 5;
$id = $m->store();

echo "store id: ";
var_export($id);
echo PHP_EOL;

// Ahora simular upsert/update
$m2 = VersaModel::dispense('items');
$m2->sku = 'X1';
$m2->qty = 10;
$res = $m2->upsert(['sku']);

echo "upsert result: ";
var_export($res);
echo PHP_EOL;

$found = VersaModel::findOne('items', ['sku' => 'X1']);

echo "found after upsert: ";
var_export($found);
echo PHP_EOL;
