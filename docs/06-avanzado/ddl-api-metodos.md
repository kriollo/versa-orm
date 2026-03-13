# API SchemaBuilder Moderna en VersaORM-PHP

Guía completa del **SchemaBuilder** moderno inspirado en Laravel para manipular esquemas de base de datos de forma fluida y transparente entre motores (MySQL, PostgreSQL, SQLite).

## ✅ Prerrequisitos
- CRUD y batch básicos
- Comprender Freeze Mode
- Necesidad real de cambio de esquema automatizado

> **Producción recomendada**: aplicar migraciones con scripts SQL auditados; el SchemaBuilder es ideal para prototipado, tooling interno, tests y desarrollo ágil.

## 🚀 Nueva API SchemaBuilder

### Acceso al SchemaBuilder

```php
use VersaORM\VersaORM;
use VersaORM\Schema\VersaSchema;

// Método 1: Instancia directa
$orm = new VersaORM($config);
$schema = $orm->schemaBuilder();

// Método 2: Facade estático (recomendado)
VersaModel::setORM($orm);
VersaSchema::setORM($orm);
// Ahora puedes usar VersaSchema::create(), etc.
```

## Tabla Resumen de Métodos

| Método | Propósito | API Anterior | Respeta Freeze | Notas |
|--------|-----------|--------------|----------------|-------|
| `VersaSchema::create()` | Crear tabla | `schemaCreate()` | ❌ (bloquea) | API fluida Laravel-like |
| `VersaSchema::table()` | Modificar tabla | `schemaAlter()` | ❌ | Alteraciones con Blueprint |
| `VersaSchema::drop()` | Eliminar tabla | `schemaDrop()` | ❌ | Soporte IF EXISTS |
| `VersaSchema::dropIfExists()` | Eliminar si existe | `schemaDrop($table, true)` | ❌ | Más explícito |
| `VersaSchema::rename()` | Renombrar tabla | `schemaRename()` | ❌ | Portable entre motores |
| `VersaSchema::hasTable()` | Verificar tabla | `schema('tables')` | ✅ | Inspección |
| `VersaSchema::hasColumn()` | Verificar columna | `schema('columns')` | ✅ | Inspección |
| `$schema->getColumns()` | Listar columnas | `schema('columns', $tabla)` | ✅ | Metadatos completos |
| `$schema->getIndexes()` | Listar índices | `schema('indexes', $tabla)` | ✅ | Información de índices |

## Creación de Tablas con API Fluida

### Ejemplo Básico
```php
use VersaORM\Schema\VersaSchema;

VersaSchema::create('users', function ($table) {
    $table->id(); // Primary key auto-increment
    $table->string('name');
    $table->string('email', 100)->unique();
    $table->timestamp('email_verified_at')->nullable();
    $table->boolean('active')->default(true);
    $table->timestamps(); // created_at, updated_at
});
```

**SQL Generado (automáticamente adaptado por motor):**

MySQL:
```sql
CREATE TABLE `users` (
  `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `email` VARCHAR(100) NOT NULL,
  `email_verified_at` TIMESTAMP NULL,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` TIMESTAMP NULL,
  `updated_at` TIMESTAMP NULL,
  UNIQUE (`email`)
);
```

PostgreSQL:
```sql
CREATE TABLE "users" (
  "id" BIGSERIAL PRIMARY KEY,
  "name" VARCHAR(255) NOT NULL,
  "email" VARCHAR(100) NOT NULL,
  "email_verified_at" TIMESTAMP NULL,
  "active" BOOLEAN NOT NULL DEFAULT TRUE,
  "created_at" TIMESTAMP NULL,
  "updated_at" TIMESTAMP NULL,
  UNIQUE ("email")
);
```

### Ejemplo Avanzado con Relaciones
```php
VersaSchema::create('posts', function ($table) {
    $table->id();
    $table->string('title', 200);
    $table->text('content');
    $table->unsignedBigInteger('user_id');
    $table->unsignedBigInteger('category_id')->nullable();
    $table->integer('views')->default(0);
    $table->boolean('published')->default(false);
    $table->json('metadata')->nullable();
    $table->decimal('price', 8, 2)->nullable();
    $table->timestamps();

    // Índices
    $table->index('title');
    $table->index(['published', 'created_at'], 'published_date_idx');

    // Claves foráneas
    $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
    $table->foreign('category_id')->references('id')->on('categories')->onDelete('set null');
});
```

## Tipos de Columna Disponibles

| Método | Tipo SQL | Descripción |
|--------|----------|-------------|
| `$table->id()` | BIGINT AUTO_INCREMENT / BIGSERIAL | Primary key auto-increment |
| `$table->string($col, $length)` | VARCHAR | Cadena variable |
| `$table->text($col)` | TEXT | Texto largo |
| `$table->integer($col)` | INT / INTEGER | Entero |
| `$table->bigInteger($col)` | BIGINT | Entero grande |
| `$table->boolean($col)` | TINYINT(1) / BOOLEAN / INTEGER | Booleano |
| `$table->decimal($col, $precision, $scale)` | DECIMAL | Decimal fijo |
| `$table->float($col, $precision, $scale)` | FLOAT | Punto flotante |
| `$table->json($col)` | JSON / TEXT | Datos JSON |
| `$table->date($col)` | DATE | Fecha |
| `$table->dateTime($col)` | DATETIME | Fecha y hora |
| `$table->timestamp($col)` | TIMESTAMP | Timestamp |
| `$table->enum($col, $values)` | ENUM / VARCHAR | Enumeración |
| `$table->uuid($col)` | CHAR(36) / UUID / TEXT | UUID |
| `$table->ipAddress($col)` | VARCHAR(45) / INET / TEXT | Dirección IP |

## Modificadores de Columna

| Método | Descripción |
|--------|-------------|
| `->nullable()` | Permite valores NULL |
| `->default($value)` | Valor por defecto |
| `->unique()` | Clave única |
| `->index()` | Crear índice |
| `->comment($text)` | Comentario |
| `->after($column)` | Posición después de columna (MySQL) |

## Modificación de Tablas

### Agregar Columnas
```php
VersaSchema::table('users', function ($table) {
    $table->string('phone', 20)->nullable();
    $table->timestamp('last_login')->nullable();
    $table->json('preferences')->nullable();
});
```

### Eliminar Columnas
```php
VersaSchema::table('users', function ($table) {
    $table->dropColumn('phone');
    $table->dropColumn(['last_login', 'preferences']); // Múltiples
});
```

### Modificar Columnas (limitado por motor)
```php
VersaSchema::table('users', function ($table) {
    $table->string('name', 150)->change(); // Cambiar longitud
});
```

### Índices y Claves
```php
VersaSchema::table('users', function ($table) {
    // Agregar índices
    $table->index('email', 'idx_users_email');
    $table->unique(['email', 'username'], 'uq_email_username');

    // Eliminar índices
    $table->dropIndex('idx_users_email');
    $table->dropUnique('uq_email_username');

    // Claves foráneas
    $table->foreign('role_id')->references('id')->on('roles');
    $table->dropForeign('users_role_id_foreign');
});
```

## Operaciones de Tabla

### Eliminar Tablas
```php
VersaSchema::drop('temp_table');
VersaSchema::dropIfExists('cache_table'); // Más seguro
```

### Renombrar Tablas
```php
VersaSchema::rename('users_old', 'users_backup');
```

### Verificación de Existencia
```php
if (VersaSchema::hasTable('users')) {
    echo "La tabla users existe\n";
}

if (VersaSchema::hasColumn('users', 'email')) {
    echo "La columna email existe en users\n";
}
```

## Inspección de Schema

### Obtener Información de Columnas
```php
$schema = $orm->schemaBuilder();
$columns = $schema->getColumns('users');

foreach ($columns as $column) {
    echo "{$column['name']} ({$column['type']})\n";
}
```

### Obtener Índices
```php
$indexes = $schema->getIndexes('users');
foreach ($indexes as $index) {
    echo "Índice: {$index['name']} en " . implode(', ', $index['columns']) . "\n";
}
```

## Transparencia entre Motores

El SchemaBuilder maneja automáticamente las diferencias entre motores:

| Característica | MySQL | PostgreSQL | SQLite |
|----------------|--------|------------|--------|
| Auto-increment | AUTO_INCREMENT | SERIAL/BIGSERIAL | INTEGER PRIMARY KEY |
| Booleanos | TINYINT(1) | BOOLEAN | INTEGER |
| JSON | JSON nativo | JSON nativo | TEXT |
| Identificadores | \`backticks\` | "quotes" | "quotes" |
| Foreign Keys | ALTER TABLE ADD | ALTER TABLE ADD | En CREATE TABLE |

## Comparación: API Antigua vs Nueva

### Antes (API antigua)
```php
// Crear tabla con API antigua
$orm->schemaCreate('users', [
    ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true],
    ['name' => 'email', 'type' => 'VARCHAR(255)', 'nullable' => false],
    ['name' => 'active', 'type' => 'BOOLEAN', 'default' => 1],
], [
    'if_not_exists' => true,
    'constraints' => [
        'unique' => [['name' => 'uq_users_email', 'columns' => ['email']]],
    ],
]);
```

### Ahora (SchemaBuilder moderno)
```php
// Crear tabla con SchemaBuilder
VersaSchema::createIfNotExists('users', function ($table) {
    $table->id();
    $table->string('email')->unique();
    $table->boolean('active')->default(true);
});
```

## Buenas Prácticas

- **Usa el facade estático**: `VersaSchema::` es más limpio y familiar para desarrolladores Laravel
- **Aprovecha la transparencia**: El mismo código funciona en MySQL, PostgreSQL y SQLite
- **Usa métodos descriptivos**: `dropIfExists()` es más claro que `drop($table, true)`
- **Agrupa cambios**: Haz múltiples modificaciones en una sola llamada a `table()`
- **Congela en producción**: Activa freeze mode para prevenir cambios accidentales

## Migración desde API Antigua

| API Antigua | SchemaBuilder Nuevo |
|-------------|-------------------|
| `$orm->schemaCreate($table, $cols, $opts)` | `VersaSchema::create($table, function($table) { ... })` |
| `$orm->schemaAlter($table, $changes)` | `VersaSchema::table($table, function($table) { ... })` |
| `$orm->schemaDrop($table, true)` | `VersaSchema::dropIfExists($table)` |
| `$orm->schemaRename($from, $to)` | `VersaSchema::rename($from, $to)` |
| `$orm->schema('columns', $table)` | `$schema->getColumns($table)` |

## Checklist SchemaBuilder

- [ ] Freeze desactivado antes de crear/alterar
- [ ] Usar facade `VersaSchema::` para consistencia
- [ ] Aprovechar métodos fluidos para definiciones claras
- [ ] Agrupar cambios relacionados en una sola operación
- [ ] Usar `hasTable()` y `hasColumn()` para verificaciones
- [ ] Planificar migración inversa (rollback)
- [ ] Re-aplicar tests de integridad tras cambios

## ➡️ Próximos Pasos
- Estrategia operacional: [DDL / Freeze / Migraciones](ddl-freeze-migraciones.md)
- Verificar impacto de cambios: [Métricas](observabilidad/metricas.md)
- Alinear tipos y casting: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
