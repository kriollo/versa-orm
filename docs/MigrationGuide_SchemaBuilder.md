# Guía de Migración: De schemaCreate() al nuevo SchemaBuilder

Esta guía muestra cómo migrar de la forma antigua de crear tablas con `schemaCreate()` a la nueva API fluida del SchemaBuilder.

## Resumen de Cambios

### ✅ Problema Resuelto: Timestamps Automáticos

El método `timestamps()` ahora genera automáticamente valores por defecto:
- `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
- `updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP` (MySQL)

### 🚀 Nueva API del SchemaBuilder

La nueva API proporciona:
- **API fluida**: Métodos encadenables y legibles
- **Tipado fuerte**: Autocompletado en IDEs
- **Abstracción automática**: Funciona igual en MySQL, PostgreSQL y SQLite
- **Timestamps automáticos**: Valores por defecto configurados automáticamente
- **Seguridad mejorada**: Validación de identificadores y prevención de inyección SQL

## Comparación: Antes vs Después

### ❌ MÉTODO ANTERIOR (Arrays)
```php
// Forma antigua con arrays (verbosa y propensa a errores)
$this->orm->schemaCreate('versa_migrations', [
    'id' => [
        'type' => 'int',
        'primary_key' => true,
        'auto_increment' => true,
        'not_null' => true
    ],
    'name' => [
        'type' => 'varchar',
        'length' => 255,
        'not_null' => true
    ],
    'created_at' => [
        'type' => 'timestamp',
        'default' => 'CURRENT_TIMESTAMP'  // Hay que recordar esto
    ],
    'updated_at' => [
        'type' => 'timestamp',
        'default' => 'CURRENT_TIMESTAMP',
        'on_update' => 'CURRENT_TIMESTAMP'  // Y esto también
    ]
], [
    'indexes' => [
        'name' => ['name']
    ],
    'unique' => [
        'name_batch' => ['name', 'batch']
    ],
    'if_not_exists' => true
]);
```

### ✅ MÉTODO NUEVO (SchemaBuilder)
```php
// Nueva forma con SchemaBuilder (limpia y mantenible)
$this->schema->create('versa_migrations', function ($table) {
    // Clave primaria autoincremental
    $table->id();

    // String no nullable
    $table->string('name', 255)->nullable(false);

    // Campos adicionales
    $table->text('description')->nullable();
    $table->integer('batch')->default(1);
    $table->timestamp('executed_at')->nullable();

    // ✨ Timestamps automáticos con valores por defecto
    $table->timestamps();

    // Índices
    $table->index('name');
    $table->unique(['name', 'batch']);

}, true); // true = IF NOT EXISTS
```

## Ventajas del Nuevo Método

### 1. **API Fluida y Legible**
```php
$table->string('email', 255)->unique()->nullable(false);
$table->decimal('price', 10, 2)->default(0.00);
$table->boolean('is_active')->default(true);
```

### 2. **Timestamps Automáticos** ✨
```php
// Antes: Tenías que recordar configurar los valores por defecto
'created_at' => [
    'type' => 'timestamp',
    'default' => 'CURRENT_TIMESTAMP'
],

// Ahora: Automático
$table->timestamps(); // ✅ Incluye valores por defecto automáticamente
```

### 3. **Abstracción Entre Motores de BD**
```php
// El mismo código funciona en MySQL, PostgreSQL y SQLite
$table->json('metadata')->nullable();
$table->uuid('external_id');
$table->timestamp('created_at')->useCurrent();
```

### 4. **Tipado Fuerte y Autocompletado**
```php
$table->string()      // Tu IDE sugiere métodos disponibles
      ->nullable()    // Encadenamiento seguro
      ->default()     // Parámetros validados
      ->unique();     // Sin errores de tipeo
```

### 5. **Menos Propenso a Errores**
```php
// Antes: Arrays con claves textuales (errores de tipeo)
'primary_key' => true,  // ¿Era 'primary_key' o 'primaryKey'?
'auto_increment' => true,  // ¿Era 'auto_increment' o 'autoIncrement'?

// Ahora: Métodos validados
$table->id();  // ✅ No hay ambigüedad
```

### 6. **Soporte Nativo para Relaciones**
```php
// Claves foráneas simplificadas
$table->integer('user_id')->unsigned();
$table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');

// O más simple:
$table->foreignId('user_id')->constrained()->onDelete('cascade');
```

## Migración Paso a Paso

### Paso 1: Identificar Tablas con schemaCreate()
Busca en tu código las llamadas a:
```php
$orm->schemaCreate('tabla_nombre', [...], [...]);
```

### Paso 2: Convertir la Estructura
```php
// Antes
$this->orm->schemaCreate('productos', [
    'id' => ['type' => 'int', 'primary_key' => true, 'auto_increment' => true],
    'nombre' => ['type' => 'varchar', 'length' => 255, 'not_null' => true],
    'precio' => ['type' => 'decimal', 'precision' => 10, 'scale' => 2, 'default' => 0.00],
    'activo' => ['type' => 'boolean', 'default' => true],
    'metadata' => ['type' => 'json', 'nullable' => true],
    'created_at' => ['type' => 'timestamp', 'default' => 'CURRENT_TIMESTAMP'],
    'updated_at' => ['type' => 'timestamp', 'default' => 'CURRENT_TIMESTAMP', 'on_update' => 'CURRENT_TIMESTAMP']
]);

// Después
$schema->create('productos', function ($table) {
    $table->id();
    $table->string('nombre', 255)->nullable(false);
    $table->decimal('precio', 10, 2)->default(0.00);
    $table->boolean('activo')->default(true);
    $table->json('metadata')->nullable();
    $table->timestamps(); // ✅ Automático
});
```

### Paso 3: Migrar Índices y Constraints
```php
// Antes
[
    'indexes' => [
        'idx_nombre' => ['nombre'],
        'idx_activo_fecha' => ['activo', 'created_at']
    ],
    'unique' => [
        'uk_nombre' => ['nombre']
    ]
]

// Después
$table->index('nombre');
$table->index(['activo', 'created_at']);
$table->unique('nombre');
```

## Testing y Validación

### Test de Migración Incluido
```php
public function testMigrateFromOldSchemaCreateToNewSchemaBuilder(): void
{
    // El test demuestra la conversión completa
    // Ubicación: testPostgreSQL/Schema/BasicSchemaBuilderTest.php
    // Ejecutar: composer test-postgresql -- --filter=testMigrateFromOldSchemaCreateToNewSchemaBuilder
}
```

### Verificación de Resultados
```php
// Verificar que la tabla se creó correctamente
$tables = $this->orm->schema('tables');
$this->assertContains('versa_migrations', $tables);

// Probar inserción con timestamps automáticos
$migrationData = ['name' => 'test_migration'];
$result = $this->orm->table('versa_migrations')->insert($migrationData);
$this->assertTrue($result > 0);
```

## Compatibilidad y Soporte

### Motores Soportados
- ✅ **MySQL 5.7+**: Completamente soportado
- ✅ **PostgreSQL 9.6+**: Completamente soportado
- ✅ **SQLite 3.8+**: Completamente soportado

### Tests de Regresión
- **PostgreSQL**: 447 tests ✅
- **MySQL**: 477 tests ✅
- **SQLite**: 398 tests ✅

### Migración Gradual
Puedes migrar gradualmente:
1. Las tablas existentes siguen funcionando
2. Nuevas tablas usan SchemaBuilder
3. Migra tablas existentes cuando sea conveniente

## Recursos Adicionales

- **Documentación completa**: `docs/04-query-builder/`
- **Ejemplos prácticos**: `example/`
- **Tests de referencia**: `testPostgreSQL/Schema/`

---

**¡La migración al nuevo SchemaBuilder te dará un código más limpio, mantenible y sin los dolores de cabeza de configurar timestamps manualmente!** ✨
