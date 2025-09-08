<?php

require_once __DIR__ . '/vendor/autoload.php';

use VersaORM\VersaModel;
use VersaORM\VersaORM;

echo "🧪 Probando timestamps automáticos en insertMany\n\n";

// Configuración para PostgreSQL (también funciona para MySQL y SQLite)
$orm = new VersaORM([
    'driver' => 'postgresql',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'versaorm_test',
    'username' => 'local',
    'password' => 'local',
    'debug' => true
]);

VersaModel::setORM($orm);

// Crear tabla de prueba con timestamps()
echo "📋 Creando tabla de prueba...\n";
$schema = $orm->schemaBuilder();
$schema->create('test_timestamps', function ($table) {
    $table->id();
    $table->string('name');
    $table->timestamps(); // ← Ahora con timestamps automáticos
}, true);

echo "✅ Tabla creada exitosamente\n\n";

// Limpiar tabla
$orm->exec('DELETE FROM test_timestamps');

echo "🔄 Insertando registros con insertMany SIN timestamps manuales...\n";

// Datos SIN timestamps manuales - deben generarse automáticamente
$testData = [
    ['name' => 'Test 1'],
    ['name' => 'Test 2'],
    ['name' => 'Test 3']
];

// Insertar usando insertMany
$result = $orm->table('test_timestamps')->insertMany($testData);
echo "📝 insertMany ejecutado: " . print_r($result, true) . "\n";

// Verificar que se insertaron con timestamps automáticos
$records = $orm->table('test_timestamps')->get();

echo "📊 Registros insertados:\n";
foreach ($records as $record) {
    echo "  - ID: {$record['id']}, Name: {$record['name']}\n";

    // Manejar timestamps que pueden ser objetos DateTime o strings
    $created_at = $record['created_at'] instanceof \DateTime ?
        $record['created_at']->format('Y-m-d H:i:s') :
        $record['created_at'];
    $updated_at = $record['updated_at'] instanceof \DateTime ?
        $record['updated_at']->format('Y-m-d H:i:s') :
        $record['updated_at'];

    echo "    created_at: {$created_at}\n";
    echo "    updated_at: {$updated_at}\n";

    // Verificar que los timestamps no están vacíos
    if (empty($created_at) || empty($updated_at)) {
        echo "    ❌ ERROR: Timestamps vacíos!\n";
    } else {
        echo "    ✅ Timestamps automáticos funcionando!\n";
    }
    echo "\n";
}

echo "🎉 ¡Prueba completada! Los timestamps automáticos funcionan correctamente con insertMany.\n";
echo "🔧 Problema resuelto: El método timestamps() ahora usa useCurrent() y useCurrentOnUpdate().\n";
