<?php

use VersaORM\QueryBuilder;

require_once __DIR__ . '/../../testSQLite/bootstrap.php';

$qb = new QueryBuilder(null, 'products');
$qb->select(['id'])->where('price', '>', 10)
    ->orWhere('stock', '<', 5)
    ->whereIn('category', [1, 2, 3])
    ->whereNull('deleted_at')
    ->whereBetween('created_at', '2020-01-01', '2020-12-31');

$ref = new ReflectionClass($qb);
$m = $ref->getMethod('buildSelectSQL');
$m->setAccessible(true);

$res = $m->invoke($qb);
print_r($res);
