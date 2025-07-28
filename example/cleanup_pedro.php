<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/index.php';

use VersaORM\VersaORM;

global $config;
$db_config = $config['DB'];

$orm = new VersaORM([
    'driver' => $db_config['DB_DRIVER'],
    'host' => $db_config['DB_HOST'],
    'port' => $db_config['DB_PORT'],
    'database' => $db_config['DB_NAME'],
    'username' => $db_config['DB_USER'],
    'password' => $db_config['DB_PASS']
]);

try {
    $orm->exec('DELETE FROM users WHERE email = ?', ['pedro@example.com']);
    echo "Pedro user deleted if existed\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
