# v1.1 - 2025-08-19
- Métodos attach, detach, sync y fresh() en BelongsToMany para gestión directa de la tabla pivot.
- Documentación actualizada para relaciones muchos-a-muchos.
- Fixes de compatibilidad con Psalm y QueryBuilder.
- Mejoras en los tests de relaciones y sincronización.
# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Added: VersaModel::storeAll(array $models) para guardar múltiples modelos y devolver array de IDs en orden.

### Añadido ⚡
- `onRaw()` en QueryBuilder para añadir expresiones complejas y seguras en la cláusula `ON` de los `JOIN`.

### Mejorado 🚀
- Motor PDO (`SqlGenerator`) ahora soporta condiciones `JOIN` mixtas estructuradas y raw con bindings parametrizados.

### Seguridad 🔒
- Validación preventiva en `onRaw()` contra sentencias múltiples (`;`), comentarios (`--`, `#`, `/* */`) y palabras DDL/DML peligrosas (DROP, ALTER, INSERT, etc.).

### Tests ✅
- Nuevos archivos de pruebas multi‑motor: `testSQLite/QueryBuilderOnRawTest.php`, `testMysql/QueryBuilderOnRawTest.php`, `testPostgreSQL/QueryBuilderOnRawTest.php` cubriendo:
  - Uso básico `onRaw`
  - Combinación con `on()` tradicional
  - Múltiples llamadas encadenadas `onRaw()`
  - Bindings aplicados correctamente
  - Rechazo de expresiones inseguras (semicolon, comentario línea, palabras peligrosas)

### Documentación 📚
- Sección añadida a `docs/user-guide/02-query-builder.md` describiendo `on()` vs `onRaw()`, casos de uso, tabla comparativa y ejemplos.

### Interno 🔧
- Ajuste en `SqlGenerator` para iterar condiciones de join y procesar entradas de tipo `raw` acumulando bindings.

---

## [1.4.0] - 2025-08-05

### Añadido ⚡
- **Completar Operaciones CRUD Faltantes (Tarea 2.2)**: Implementación integral de operaciones CRUD avanzadas
  - Método `upsert()` individual para inserción inteligente con detección automática de duplicados
  - Método `insertOrUpdate()` como alias intuitivo para operaciones upsert
  - Método `save()` inteligente que detecta automáticamente si es INSERT o UPDATE
  - Método `createOrUpdate()` con condiciones personalizadas y validación avanzada
  - Método `replaceInto()` para compatibilidad específica MySQL con reemplazo completo
  - Integración completa en VersaModel con validación automática y manejo de errores
  - Soporte multi-base de datos con sintaxis específica para cada motor:
    - MySQL: `INSERT ... ON DUPLICATE KEY UPDATE`
    - PostgreSQL: `INSERT ... ON CONFLICT DO UPDATE`
    - SQLite: `INSERT OR REPLACE INTO`

### Mejorado 🚀
- **QueryBuilder**: Ampliado con 5 nuevos métodos CRUD (líneas 1580-2100+)
  - Validación completa de datos de entrada con sanitización automática
  - Manejo inteligente de claves únicas y detección de conflictos
  - Fallback automático para bases de datos sin soporte nativo
  - Integración con freeze mode para protección de esquema
- **VersaModel**: Extensión con métodos CRUD a nivel de modelo (líneas 800-1000+)
  - Auto-detección de claves únicas desde metadatos de esquema
  - Validación automática antes de operaciones de escritura
  - Manejo consistente de errores con excepciones descriptivas
- **Núcleo Rust**: Implementación completa en el backend (main.rs líneas 1020-1120)
  - Manejo nativo de operaciones `"upsert"` con validación de parámetros
  - Construcción SQL optimizada específica por base de datos
  - Validación estricta de claves únicas y columnas de actualización

### Técnico 🔧
- Añadidos tests unitarios completos (`versaorm_cli/src/tests/replace_and_upsert_tests.rs`)
  - Tests de validación de estructura JSON (514 líneas)
  - Tests de construcción SQL específica por base de datos
  - Tests de manejo de errores y casos edge
- **Nuevos tests PHP específicos para operaciones individuales**:
  - `tests/UpsertOperationsTest.php`: 16 tests completos para upsert(), insertOrUpdate(), save(), createOrUpdate()
  - `tests/ReplaceIntoTest.php`: 12 tests completos para replaceInto() con casos de uso específicos
  - Total: 28 tests nuevos con 151 aserciones que validan todos los métodos CRUD individuales
- Tests PHP existentes actualizados (`QueryBuilderBatchTest.php`)
  - Validación de `upsertMany` para operaciones batch
  - Tests de validación de parámetros y casos límite
- Validación completa de seguridad con `clean_column_name()` en todas las operaciones
- Manejo robusto de errores con propagación correcta desde Rust a PHP

### Documentación 📚
- Nueva guía completa: [Operaciones UPSERT y REPLACE INTO](docs/user-guide/11-upsert-replace-operations.md) (742 líneas)
  - Documentación exhaustiva con ejemplos prácticos de todos los métodos
  - Comparativas detalladas UPSERT vs REPLACE INTO vs INSERT/UPDATE tradicional
  - Casos de uso específicos: inventarios, configuraciones, contadores, sincronización
  - Guías de mejores prácticas y optimización de rendimiento
- Actualización del índice de documentación (`docs/user-guide/README.md`)
  - Integración de nuevos métodos en la navegación
  - Enlaces cruzados con ejemplos rápidos
- Ejemplos prácticos en guía rápida (`docs/user-guide/12-query-builder-quick-examples.md`)

### Calidad y Estándares 📋
- ✅ Código PHP con PSR-12 compliance y validación completa
- ✅ Código Rust con convenciones estándar y manejo de errores robusto
- ✅ Tests unitarios completos con cobertura de casos edge
- ✅ Documentación exhaustiva con ejemplos listos para usar
- ✅ Integración perfecta con arquitectura existente PHP + Rust
- ✅ Validación de seguridad en todas las operaciones de entrada

### Ejemplos de Uso
```php
// Nuevo: UPSERT inteligente - insertar si no existe, actualizar si existe
$result = $orm->table('products')->upsert(
    ['sku' => 'PROD001', 'name' => 'Laptop Pro', 'price' => 1500.00],
    ['sku'], // Claves únicas para detectar duplicados
    ['name', 'price'] // Columnas a actualizar si existe
);

// Nuevo: Método save() inteligente
$user = $orm->table('users')->where('email', '=', 'john@example.com')->first();
if (!$user) {
    $user = ['email' => 'john@example.com'];
}
$user['name'] = 'John Updated';
$result = $orm->table('users')->save($user, ['email']);

// Nuevo: insertOrUpdate con validación automática
$result = $orm->table('settings')->insertOrUpdate(
    ['key' => 'app_version', 'value' => '2.1.0'],
    ['key']
);
```

## [1.3.0] - 2025-08-06

### Añadido ⚡
- **Operaciones UPSERT y REPLACE INTO**: Nuevas operaciones avanzadas de inserción/actualización inteligente
  - Método `upsert()` individual para inserción inteligente (insertar si no existe, actualizar si existe)
  - Método `replaceInto()` individual para reemplazo completo (solo MySQL)
  - Método `replaceIntoMany()` para reemplazos masivos optimizados (solo MySQL)
  - Soporte para múltiples claves únicas en operaciones upsert
  - Control granular de columnas a actualizar con parámetro `updateColumns`
  - Validación automática de drivers de base de datos (REPLACE INTO solo para MySQL)
  - Implementación fallback robusta que funciona en todas las bases de datos
  - Manejo inteligente de tablas sin columna `id` autoincremental

### Mejorado 🚀
- **Operaciones Batch**: Ampliadas las operaciones de lote existentes
  - `upsertMany()` ahora disponible para operaciones masivas de upsert
  - Integración perfecta con las operaciones batch existentes
  - Procesamiento por lotes optimizado para grandes volúmenes de datos
- **Seguridad**: Validación estricta de nombres de columnas y claves únicas
- **Compatibilidad**: Implementación que funciona con y sin soporte nativo del binario Rust

### Técnico 🔧
- Añadidos 22 tests completos para operaciones UPSERT y REPLACE INTO (`QueryBuilderReplaceAndUpsertTest.php`)
- Actualización de `VersaoORM.php` para incluir nuevas acciones válidas
- Correcciones en el esquema de pruebas (tabla `products` con columnas faltantes)
- Implementación fallback que utiliza SQL raw para compatibilidad universal
- Manejo robusto de errores con mensajes descriptivos
- Integración completa con tests existentes (84+ tests pasando)

### Documentación 📚
- Nueva guía completa: [Operaciones UPSERT y REPLACE INTO](docs/user-guide/11-upsert-replace-operations.md)
- Actualización de [Operaciones de Lote](docs/user-guide/03-batch-operations.md) con `replaceIntoMany()`
- Comparaciones detalladas entre SQL tradicional vs VersaORM
- Ejemplos prácticos para casos de uso comunes:
  - Sincronización con APIs externas
  - Sistemas de caché inteligente
  - Contadores de actividad
  - Configuraciones de usuario
- Guías de mejores prácticas y manejo de errores
- Documentación de diferencias críticas entre UPSERT y REPLACE INTO

### Ejemplos de Uso
```php
// UPSERT - Inserción inteligente con control granular
$result = $orm->table('products')->upsert(
    ['sku' => 'PROD001', 'name' => 'Laptop Pro', 'price' => 1500.00],
    ['sku'],              // Claves únicas para detectar duplicados
    ['name', 'price']     // Solo actualizar estos campos si existe
);

// REPLACE INTO - Reemplazo completo (solo MySQL)
$result = $orm->table('products')->replaceInto([
    'sku' => 'PROD001',
    'name' => 'Laptop Pro Updated',
    'price' => 1600.00,
    'description' => 'Nueva descripción completa'
]);

// OPERACIONES MASIVAS optimizadas
$result = $orm->table('products')->replaceIntoMany($products, 1000);
```

### Casos de Uso Resueltos
- ✅ Sincronización de inventario desde APIs externas
- ✅ Sistemas de configuración que requieren reemplazo completo
- ✅ Contadores y estadísticas con actualización inteligente
- ✅ Cachés con tiempo de vida y contadores de acceso
- ✅ Preferencias de usuario con claves compuestas

### Migración
- **Cambios Breaking**: Ninguno - Completamente compatible con código existente
- **Nueva API**: Opcional - Nuevos métodos `upsert()`, `replaceInto()` y `replaceIntoMany()`
- **Compatibilidad**: Funciona en MySQL, PostgreSQL, SQLite (con fallbacks automáticos)

---

## [1.2.0] - 2025-08-05

### Añadido ⚡
- **Modo Lazy y Planificador de Consultas**: Nueva funcionalidad revolucionaria que optimiza automáticamente las consultas complejas
  - Método `->lazy()` para activar modo de optimización automática
  - Método `->collect()` para ejecutar consultas optimizadas
  - Planificador inteligente que combina WHERE clauses y optimiza JOINs automáticamente
  - Método `->explain()` para visualizar el plan de ejecución optimizado
  - Soporte completo para consultas complejas con múltiples JOINs y condiciones
  - Sistema de caching inteligente para planes de consulta reutilizables

### Mejorado 🚀
- **Rendimiento**: Las consultas complejas ahora son significativamente más rápidas con optimización automática
- **Query Builder**: Integración perfecta del modo lazy con API existente
- **Rust Core**: Nuevas funciones de optimización en el núcleo Rust para análisis de consultas

### Técnico 🔧
- Añadidos 12 tests completos para el modo lazy (`LazyQueryPlannerTest.php`)
- Integración completa con infraestructura existente de tests
- Análisis estático completado con PHPStan nivel 8 (0 errores)
- Análisis de calidad con cargo clippy (0 warnings)
- Binario Rust compilado y deployado en `src/binary/versaorm_cli.exe`

### Documentación 📚
- Nueva guía completa: [Modo Lazy y Planificador de Consultas](docs/user-guide/10-lazy-mode-query-planner.md)
- Ejemplos detallados de "antes vs después" mostrando mejoras de rendimiento
- Integración de ejemplos lazy en todas las guías existentes
- Actualización del README principal con nueva funcionalidad
- Documentación de mejores prácticas para uso del modo lazy

### Ejemplos de Uso
```php
// ANTES: Múltiples construcciones SQL
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->orderBy('created_at', 'desc')
    ->getAll();

// AHORA: Una sola consulta optimizada automáticamente
$users = $orm->table('users')
    ->lazy()                           // 🚀 Activa optimización automática
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->orderBy('created_at', 'desc')
    ->collect();                       // ✅ Ejecuta consulta optimizada
```

### Migración
- **Cambios Breaking**: Ninguno - Completamente compatible con código existente
- **Nueva API**: Opcional - Solo usar `->lazy()` y `->collect()` cuando se desee optimización automática

---

## [1.1.0] - 2025-07-30

### Añadido
- Sistema de caché básico
- Validación avanzada con Mass Assignment Protection
- Tipado fuerte y validación de esquemas
- Modo Freeze para protección de esquema en producción

### Mejorado
- Rendimiento general del ORM
- Seguridad contra inyección SQL
- Compatibilidad con múltiples bases de datos

---

## [1.0.0] - 2025-07-15

### Añadido
- Lanzamiento inicial de VersaORM-PHP
- Query Builder completo
- Sistema de modelos Active Record
- Núcleo Rust para máximo rendimiento
- Soporte para MySQL, PostgreSQL, SQLite
- Documentación completa
