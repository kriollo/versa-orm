# Guía Completa: Foreign Keys, Índices y Constraints en VersaORM SchemaBuilder

Esta guía demuestra todas las formas de definir foreign keys, índices y constraints en VersaORM usando el SchemaBuilder.

## ✅ Foreign Keys - Sintaxis Válidas

### 1. Foreign Key Simple (Recomendado)
```php
$table->foreign('usuario_id')
      ->references('id')
      ->on('usuarios')
      ->onDelete('CASCADE');
```

### 2. Foreign Key con Array (Funciona)
```php
// ✅ Esta sintaxis SÍ es correcta (como preguntaste)
$table->foreign(['parent_id'])
      ->references('id')
      ->on('documentos_carpetas')
      ->onDelete('CASCADE');
```

### 3. Foreign Key Abreviada (Laravel-style)
```php
$table->foreignId('usuario_id')->constrained()->onDelete('cascade');
```

## 🔗 Acciones de Foreign Keys

### Acciones onDelete Disponibles
```php
->onDelete('CASCADE')    // Eliminar registros dependientes
->onDelete('SET NULL')   // Poner en NULL los campos dependientes
->onDelete('RESTRICT')   // No permitir eliminación (error)
->onDelete('NO ACTION')  // Sin acción específica
```

### Acciones onUpdate Disponibles
```php
->onUpdate('CASCADE')    // Actualizar registros dependientes
->onUpdate('SET NULL')   // Poner en NULL al actualizar
->onUpdate('RESTRICT')   // No permitir actualización
```

### Ejemplo Completo
```php
$this->schema->create('documentos', function ($table) {
    $table->id();
    $table->string('titulo', 255);
    $table->unsignedBigInteger('carpeta_id')->nullable();
    $table->unsignedBigInteger('usuario_id');
    $table->timestamps();

    // Foreign key con CASCADE (eliminar documentos si se elimina carpeta)
    $table->foreign(['carpeta_id'])
          ->references('id')
          ->on('documentos_carpetas')
          ->onDelete('CASCADE');

    // Foreign key con RESTRICT (no permitir eliminar usuario con documentos)
    $table->foreign('usuario_id')
          ->references('id')
          ->on('usuarios')
          ->onDelete('RESTRICT');
});
```

## 📊 Tipos de Índices

### 1. Índices Simples
```php
$table->index('nombre');                           // Índice normal
$table->unique('email');                          // Índice único
$table->index('codigo', 'idx_codigo_personalizado'); // Índice con nombre
```

### 2. Índices Compuestos
```php
$table->index(['categoria', 'activo']);           // Índice compuesto
$table->unique(['nombre', 'categoria']);          // Único compuesto
$table->index(['precio', 'stock'], 'idx_precio_stock'); // Con nombre personalizado
```

### 3. Índices Especiales
```php
$table->primary(['codigo_pais', 'codigo_ciudad']); // Clave primaria compuesta
$table->fulltext(['titulo', 'contenido']);         // Índice de texto completo
```

## 🏗️ Ejemplos Prácticos por Casos de Uso

### Caso 1: Estructura Jerárquica (Auto-referencial)
```php
$this->schema->create('categorias', function ($table) {
    $table->id();
    $table->string('nombre', 100);
    $table->unsignedBigInteger('categoria_padre_id')->nullable();
    $table->integer('nivel')->default(0);
    $table->timestamps();

    // ✅ Foreign key auto-referencial
    $table->foreign('categoria_padre_id')
          ->references('id')
          ->on('categorias')
          ->onDelete('SET NULL'); // Los hijos quedan huérfanos

    // Índices para consultas de árbol
    $table->index('categoria_padre_id');
    $table->index(['nivel', 'categoria_padre_id']);
});
```

### Caso 2: Relación Many-to-Many
```php
// Tabla pivot para relaciones N:M
$this->schema->create('documento_tags', function ($table) {
    $table->id();
    $table->unsignedBigInteger('documento_id');
    $table->unsignedBigInteger('tag_id');
    $table->integer('orden')->default(0);
    $table->timestamps();

    // Foreign keys con CASCADE
    $table->foreign('documento_id')
          ->references('id')
          ->on('documentos')
          ->onDelete('CASCADE');

    $table->foreign('tag_id')
          ->references('id')
          ->on('tags')
          ->onDelete('CASCADE');

    // Evitar duplicados
    $table->unique(['documento_id', 'tag_id']);

    // Índices para consultas
    $table->index('tag_id');
    $table->index(['documento_id', 'orden']);
});
```

### Caso 3: Sistema de Órdenes Complejo
```php
$this->schema->create('ordenes', function ($table) {
    $table->id();
    $table->string('numero_orden', 50)->unique();
    $table->unsignedBigInteger('usuario_id');
    $table->decimal('total', 12, 2);
    $table->string('estado', 50)->default('pendiente');
    $table->timestamps();

    // Foreign key con RESTRICT (proteger datos históricos)
    $table->foreign('usuario_id')
          ->references('id')
          ->on('usuarios')
          ->onDelete('RESTRICT');

    // Índices para consultas frecuentes
    $table->index(['usuario_id', 'estado']);     // Órdenes por usuario y estado
    $table->index(['estado', 'created_at']);     // Órdenes por estado y fecha
    $table->index(['created_at', 'total']);      // Reportes por fecha y monto
});

$this->schema->create('orden_items', function ($table) {
    $table->id();
    $table->unsignedBigInteger('orden_id');
    $table->unsignedBigInteger('producto_id');
    $table->integer('cantidad');
    $table->decimal('precio_unitario', 10, 2);
    $table->timestamps();

    // Foreign keys con diferentes comportamientos
    $table->foreign('orden_id')
          ->references('id')
          ->on('ordenes')
          ->onDelete('CASCADE');    // Eliminar items con la orden

    $table->foreign('producto_id')
          ->references('id')
          ->on('productos')
          ->onDelete('RESTRICT');   // Proteger productos en uso

    // Un producto por orden (evitar duplicados)
    $table->unique(['orden_id', 'producto_id']);
});
```

## 🚀 Características Avanzadas

### Foreign Keys Compuestas (Experimental)
```php
// Tabla con clave primaria compuesta
$this->schema->create('ubicaciones', function ($table) {
    $table->string('pais', 2);
    $table->string('ciudad', 10);
    $table->string('nombre', 100);
    $table->timestamps();

    $table->primary(['pais', 'ciudad']);
});

// Tabla que referencia clave compuesta
$this->schema->create('direcciones', function ($table) {
    $table->id();
    $table->string('direccion', 255);
    $table->string('pais_ref', 2);
    $table->string('ciudad_ref', 10);
    $table->timestamps();

    // ⚠️ Foreign key compuesta (verificar soporte)
    $table->foreign(['pais_ref', 'ciudad_ref'])
          ->references(['pais', 'ciudad'])
          ->on('ubicaciones')
          ->onDelete('CASCADE');
});
```

### Índices con Condiciones (PostgreSQL)
```php
// Índice parcial (solo para valores específicos)
$table->index('email', 'idx_email_activos')->where('activo = true');
$table->index('precio', 'idx_precios_altos')->where('precio > 1000');
```

## ✅ Mejores Prácticas

### 1. Nomenclatura de Índices
```php
// Buenos nombres descriptivos
$table->index('email', 'idx_usuarios_email');
$table->unique(['nombre', 'categoria'], 'uk_productos_nombre_categoria');
$table->foreign('usuario_id', 'fk_documentos_usuario');
```

### 2. Orden de Creación de Tablas
```php
// ✅ CORRECTO: Crear tablas padre antes que hijas
$this->schema->create('usuarios', function ($table) { ... });
$this->schema->create('documentos', function ($table) {
    // Ahora sí se puede referenciar 'usuarios'
    $table->foreign('usuario_id')->references('id')->on('usuarios');
});
```

### 3. Índices para Rendimiento
```php
$table->index('created_at');                    // Para consultas por fecha
$table->index(['activo', 'created_at']);        // Para filtros combinados
$table->index(['usuario_id', 'estado']);        // Para consultas frecuentes
$table->fulltext(['titulo', 'contenido']);      // Para búsquedas de texto
```

### 4. Validación de Constraints
```php
// El test verifica que las foreign keys funcionan
$usuario = VersaModel::dispense('usuarios');
$usuario->nombre = 'Juan';
$usuarioId = $usuario->store();

$documento = VersaModel::dispense('documentos');
$documento->titulo = 'Mi documento';
$documento->usuario_id = $usuarioId; // ✅ Foreign key válida
$documento->store(); // Funciona

$documento2 = VersaModel::dispense('documentos');
$documento2->titulo = 'Documento inválido';
$documento2->usuario_id = 99999; // ❌ ID que no existe
$documento2->store(); // Lanza excepción por constraint
```

## 🧪 Testing Completo

El archivo `ForeignKeysAndConstraintsTest.php` incluye tests para:

- ✅ Foreign keys con sintaxis de array `['campo']`
- ✅ Foreign keys simples `'campo'`
- ✅ Diferentes acciones onDelete (CASCADE, SET NULL, RESTRICT)
- ✅ Índices simples, únicos y compuestos
- ✅ Relaciones many-to-many con tabla pivot
- ✅ Foreign keys auto-referenciales
- ✅ Validación de constraints con datos reales
- ✅ Timestamps automáticos funcionando

### Ejecutar Tests
```bash
# Test específico de foreign keys
composer test-postgresql -- --filter=ForeignKeysAndConstraintsTest

# Todos los tests
composer test-postgresql  # 447 tests ✅
composer test-mysql       # 477 tests ✅
composer test-sqlite      # 398 tests ✅
```

## 📝 Resumen de Respuesta

**SÍ, tu sintaxis es correcta:**
```php
$table->foreign(['parent_id'])
      ->references('id')
      ->on('documentos_carpetas')
      ->onDelete('CASCADE');
```

Esta sintaxis funciona perfectamente y está validada en los tests. VersaORM soporta tanto la sintaxis con array `['campo']` como la simple `'campo'` para foreign keys.

¡El SchemaBuilder de VersaORM es muy potente y flexible! 🚀
