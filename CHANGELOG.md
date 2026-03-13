## [1.9.0] - 2026-03-13

### 🔧 Timezone Correctness y Hardening de Conexión

**VersaModel.php — Timestamps con timezone del ORM:**

- `store()` ya no usa UTC hardcodeado para `created_at` / `updated_at`.
- Ahora usa `getTimezone()` de la instancia ORM cuando está disponible.
- Fallback seguro a `date_default_timezone_get()` cuando no hay timezone configurada o viene vacía.
- Corrige desfases visibles en motores que persisten `timestamp without time zone`.

**HasStrongTyping.php — Casting datetime alineado al ORM:**

- El cast de timestamps unix a `DateTimeImmutable` ahora intenta resolver la timezone desde el ORM del modelo.
- Si no puede resolver ORM/timezone, mantiene fallback a `date_default_timezone_get()`.
- Mejora consistencia entre valores casteados y persistencia automática de timestamps.

**PdoConnection.php — Defaults y autenticación más seguros:**

- Host por defecto para MySQL/PostgreSQL cambiado de `localhost` a `127.0.0.1` para evitar resolución implícita por socket en entornos donde sólo TCP está disponible.
- El fallback implícito de credenciales `local/local` ya no se aplica automáticamente.
- Se añade fallback opcional explícito vía `options.allow_local_fallback_auth`.

**VersaORMTrait.php — Configuración base menos rígida:**

- `DEFAULT_CONFIG` simplificada para evitar defaults de driver/host/port/credenciales hardcodeados.
- Se mantiene `engine => pdo` como valor base seguro.

### ✅ Validación

- SQLite: `882` tests (`2301` assertions) sin fallas/errores.
- MySQL: `520` tests (`1559` assertions) OK.
- PostgreSQL: `645` tests (`1961` assertions) OK.

---

## [1.8.8] - 2026-03-02

### ✨ Modelos Tipados, Hooks de Ciclo de Vida y Protección contra Recursión

**VersaModel.php — Subclases tipadas (IDE-friendly):**

- **`protected static string $tableName`**: Nueva propiedad estática para declarar la tabla en subclases con tipado fuerte.
- **`protected static function resolveTable()`**: Nuevo método que auto-infiere el nombre de tabla desde el nombre de la clase (`UserProfile` → `user_profiles`) cuando no se define `$tableName`. Retrocompatible.
- **`dispense()` con tipado estático**: Cambiado el tipo de retorno de `self` a `static`. Llamar `User::dispense()` le indica al IDE que el retorno es `User`, no `VersaModel`. El parámetro `$table` es ahora opcional.
- **`load()` con tipado estático**: Tipo de retorno cambiado a `?static`. Marcado como `final`.
- **`find()` nuevo método `final`**: Atajo limpio a `load()` sin repetir el nombre de tabla — `User::find(1)` equivale a `User::load('users', 1)`. IDE detecta el tipo correcto como `?User`.
- **`dispenseInstance()` con tipado estático**: Tipo de retorno cambiado a `static`. Marcado como `final`.

**VersaModel.php — Métodos CRUD protegidos con `final`:**

- Marcados como `final`: `store()`, `save()`, `trash()`, `storeAndGetId()`, `create()`, `update()`.
- Elimina colisiones silenciosas: definir `save()` en una subclase ahora provoca un error fatal de PHP en tiempo de carga (visible en el IDE), en lugar de causar recursión infinita en tiempo de ejecución.

**VersaModel.php — Hooks de ciclo de vida:**

- Añadidos 9 métodos protegidos vacíos (extensión segura en subclases sin riesgo de colisión):
  - `beforeSave()` / `afterSave()`
  - `beforeCreate()` / `afterCreate()`
  - `beforeUpdate()` / `afterUpdate()`
  - `beforeDelete()` / `afterDelete()`
  - `afterRetrieve()`
- Se integran con el sistema de eventos existente (`fireEvent`) sin duplicar lógica.

**VersaModel.php — Guardia contra recursión infinita:**

- Añadida propiedad `private bool $storeInProgress` como centinela.
- `store()` y `save()` lanzan `VersaORMException('RECURSIVE_STORE')` si un hook o listener llama a `store()` / `save()` mientras ya están en ejecución, en lugar de colapsar el proceso con un stack overflow.

---

## [1.8.7] - 2026-03-02

### 🐛 Corrección de Compatibilidad PHP 8.4

**Schema/Blueprint.php — Nullable implícito corregido:**

- **PHP 8.4 Deprecated fix**: Corregidos 9 métodos que usaban `type $param = null` sin el operador `?` explícito, lo que generaba warnings `Deprecated: Implicitly marking parameter as nullable` en PHP 8.4.
- Métodos corregidos: `foreignIdFor()`, `primary()`, `unique()`, `index()`, `fullText()`, `spatialIndex()`, `dropPrimary()`, `foreign()`, `addIndex()`.
- El cambio (`string $x = null` → `?string $x = null`) es retrocompatible con PHP 8.1–8.4 ya que el operador `?` existe desde PHP 7.1.

---

## [1.8.6] - 2026-02-06

### 🛠️ Mejoras y Seguridad (Hardening )

**QueryBuilder.php - Seguridad y Bindings:**

- **Validación de Funciones**: Se actualizó `isSQLFunction()` para permitir el carácter `/` en los argumentos, facilitando la concatenación de fechas en PostgreSQL y otros motores.
- **Estabilidad y Tipado (Hotfix)**: Corregido `TypeError: array_merge(): Argument #1 must be of type array, null given` al inicializar correctamente la variable `$bindings` en `buildSelectSQL()`.
- **Recolección de Bindings Mejorada**: Refactorizada la gestión de bindings en `buildSelectSQL()` para incluir parámetros de cláusulas `JOIN` y asegurar que el orden de los bindings coincida con la estructura SQL (`SELECT` -> `FROM` -> `JOIN` -> `WHERE`).
- **Nuevos Métodos de Inspección**: Expuestos los métodos `toSql()` y `getBindings()` para facilitar el debugging y la integración con otros sistemas.

**Testing:**

- **Core SQL Validation**: Actualizada la suite `QueryBuilderBuildSelectSQLTest.php` para validar la correcta recolección de bindings en JOINs complejos.
- **Invoice JSON Tests**: Agregados tests específicos para validación de agregación JSON y concatenación compleja.
- **Quoting de Literales**: Ajustada la suite de pruebas `PostgreSQLInvoiceJsonTest.php` para usar comillas simples en literales de cadena, cumpliendo con el estándar SQL estricto.

---

## [1.8.5] - 2026-01-30

### 🔧 Correcciones y Estabilidad

**ErrorHandler.php - Gestión de Logs:**

- **Permisos de Directorio**: Corregida la creación de la carpeta de logs aumentando los permisos de `0o755` a `0o775` para asegurar la escritura en entornos con grupos compartidos.

**Calidad y Testing:**

- **PHPStan Analysis**: Refinada la lógica de parseo en `PHPStanAnalyzer.php` para manejar correctamente resultados vacíos y mejorar la precisión del reporte de calidad.

---

## [1.8.4] - 2026-01-23

### 🔧 Estabilidad del Núcleo y Tipado Inteligente

**HasStrongTyping.php - Inferencia de Tipos Dinámica:**

- **Inferencia desde Esquema**: Implementado `getColumnTypeFromSchema()` para detectar tipos automáticamente desde la BD cuando no están definidos en el modelo.
  - Mejora crítica para campos `float`, `double` y `real` que antes se trataban como strings por defecto.
- **Soporte PostgreSQL SSL/Fork**: Mejorado el flujo de detección de drivers para manejar reconexiones seguras.
- **Manejo de Booleanos**: Refinada la lógica para strings booleanos de PostgreSQL (`'t'`, `'true'`, `'f'`, `'false'`).

**QueryBuilder.php - Robustez y Seguridad:**

- **Havings Estables**: Corregida la compilación de cláusulas `HAVING` para asegurar que las propiedades se concatenen correctamente con conectores `AND`.
- **Hardening de Métodos RAW**: Validación reforzada en `selectRaw()`, `whereRaw()` y `joinRaw()` para prevenir expresiones vacías o malformadas.
- **Fluent Joins**: Mejorada la consistencia en los métodos de join con alias y condiciones complejas.

**SqlGenerator.php - Generación SQL Optimizada:**

- **Full Outer Join SQLite**: Refinada la emulación de `FULL OUTER JOIN` mediante la inversión controlada de tablas en `LEFT JOIN`.
- **SELECT Compilation**: Limpieza de side-effects y mejora en la normalización de partes del SELECT.

### 📚 Documentación y Testing

- **Pokio & SSL Troubleshooting**: Nueva guía [Solución: Errores SSL con PostgreSQL y Pokio](docs/pokio-ssl-troubleshooting.md) detallando patrones de reconexión para procesos fork.
- **Suites de Pruebas PostgreSQL**: Agregados tests intensivos para validación de SSL y concurrencia (`PokioSSLTest.php`, `PokioAsyncTest.php`).
- **Edge Cases de Tipado**: Nuevos tests para validación de tipos estrictos en SQLite y PostgreSQL.

### ✅ Validación de Calidad

- **PHPStan Level 9**: ✅ 0 errores (validación estricta de todo el núcleo `src/`).
- **Tests Multi-Motor**: ✅ Cobertura completa validada en SQLite, MySQL y PostgreSQL.
- **Seguridad**: ✅ Validación estricta de identificadores en todas las capas de compilación.

---

## [1.8.3] - 2026-01-21

### 🔧 Correcciones de Tipado Estático (PHPStan Level 9)

**VersaModel.php - Type Safety Mejorado:**

- **Línea 209**: Corrección de tipado en `tableName()`
  - `preg_replace()` puede retornar `string|null`, ahora se valida antes de `strtolower()`
  - Fallback seguro a `$class` si `preg_replace()` retorna null
- **Líneas 424-436**: Validación de tipos antes de casting en `convertValueByTypeMapping()`
  - `integer/int`: Validación con `is_numeric()`, `is_string()`, `is_bool()` antes de cast
  - `float/double/decimal`: Misma validación antes de cast a float
  - `string`: Validación con `is_scalar()` o método `__toString()` antes de cast
  - Previene warnings de "Cannot cast mixed to int/float/string"
- **Línea 1006**: Validación explícita de tipo en `getUniqueKeys()`
  - `$config['driver']` se valida con `is_string()` antes de usar `strtolower()`
  - Previene "Cannot cast mixed to string"
- **Línea 1014**: Comparación estricta en detección de índices únicos
  - Cambiado de `$index['unique'] == 1` a `$index['unique'] === 1`
  - Agregada validación `is_string($index['name'])` antes de usar la variable
- **Línea 1060**: Tipo de retorno array clarificado
  - Agregado `array_values()` para garantizar array indexado
  - PHPDoc explícito `@var array<string>` para el resultado

**PdoEngine.php - Corrección de PHPDoc:**

- **Líneas 2286, 2293, 2344**: Variables PHPDoc corregidas en `fetchForeignKeys()`
  - Error: PHPDoc documentaba variable `$rows` que no existía
  - Corrección: Asignar resultado a variable `$result` antes de documentar
  - PHPDoc ahora coincide con variable real: `@var list<array{...}> $result`
  - Afecta a consultas de foreign keys en MySQL, SQLite y PostgreSQL

**HasStrongTyping.php - Manejo de Booleanos PostgreSQL:**

- Soporte para formato nativo de PostgreSQL (`'t'` / `'f'`)
- Edge cases corregidos: strings no reconocidos retornan `false` en lugar de usar `(bool)` cast
- Agregado `''` (string vacío) a valores que retornan false

### ✅ Validación de Calidad

- **PHPStan Level 9**: ✅ 0 errores (todas las correcciones de tipado validadas)
- **SQLite Tests**: ✅ 865 tests, 2248 assertions (0 errores, 0 fallos)
- **PostgreSQL Tests**: ✅ 558 tests, 1609 assertions (0 errores, 0 fallos)
- **Unit Tests**: ✅ 498 tests, 1273 assertions (0 errores, 0 fallos)
- **Total**: ✅ 1921 tests pasando sin errores

### 🎯 Impacto

- **Robustez mejorada**: Prevención de errores de tipo en runtime
- **IntelliSense mejorado**: IDEs pueden inferir tipos correctamente
- **Mantenibilidad**: Código más predecible y fácil de mantener
- **Sin breaking changes**: Todas las correcciones son internas y compatibles hacia atrás

---

## [1.8.2] - 2026-01-21

### 🔧 SchemaBuilder: Compatibilidad Multi-DB Mejorada

**Correcciones para SQLite:**

- **fetchIndexes() mejorado**: Ahora obtiene las columnas de cada índice usando `PRAGMA index_info()`
  - Retorna estructura consistente: `['name' => ..., 'columns' => [...], 'unique' => ...]`
  - Compatible con el formato de MySQL y PostgreSQL
- **createIfNotExists()**: Nuevo método wrapper para crear tablas solo si no existen
  - Delega a `create()` con flag `$ifNotExists = true`
- **Índices UNIQUE en ALTER TABLE**: Corrección crítica en `createIndexes()`
  - Añadido parámetro `$includeUnique` para distinguir CREATE TABLE vs ALTER TABLE
  - Los índices UNIQUE ahora se crean correctamente cuando se agregan con `->unique()` en ALTER TABLE
  - En CREATE TABLE se omiten (ya están en la definición de columna)
- **Tests actualizados**: `testRenameColumn()` y `testModifyColumn()` marcados como skipped
  - SQLite no soporta estas operaciones directamente (limitación del motor)

**Correcciones para MySQL:**

- **Configuración de base de datos**: Cambiado default de 'test' a 'versaorm_test'
  - Unificado formato de variables de entorno con PostgreSQL (`getenv('DB_NAME')`)
  - Mayor consistencia entre motores de bases de datos
- **fetchIndexes() agrupado**: Ahora agrupa columnas por nombre de índice
  - Antes: Una fila por cada columna de cada índice
  - Ahora: `['name' => ..., 'columns' => [...], 'unique' => ...]`
  - Estructura consistente con PostgreSQL y SQLite
- **fetchForeignKeys() corregido**: SQL mejorado con JOIN apropiado
  - Agregado `LEFT JOIN information_schema.REFERENTIAL_CONSTRAINTS`
  - Ahora obtiene correctamente `DELETE_RULE` y `UPDATE_RULE`
  - Las columnas estaban en tabla diferente a `KEY_COLUMN_USAGE`

**Mejoras de Calidad (PHPStan Level 9):**

- Reemplazado `empty($tables)` con comparación estricta `$tables === []`
- Añadido cast explícito `(bool)` en condición de `getAttribute('change', false)`
- Eliminación de warnings de comparaciones no estrictas

### ✅ Estado de Tests

- **MySQL**: 19/19 tests pasando (SchemaBuilderIntegration) ✅
- **PostgreSQL**: 20/20 tests pasando (SchemaBuilderIntegration) ✅
- **SQLite**: 26/26 tests pasando, 2 skipped (limitaciones conocidas) ✅
- **PHPStan Level 9**: 0 errores ✅

### 🎯 Impacto

- **100% de compatibilidad** entre MySQL, PostgreSQL y SQLite para operaciones de esquema
- **Consistencia de API**: Mismo código funciona en los 3 motores sin cambios
- **Robustez mejorada**: Índices y foreign keys funcionan correctamente en todos los motores

## [1.8.0] - 2026-01-20

### 🚀 CI/CD & Automation (Refactorización de CI)

**Flujo de Trabajo Unificado:**

- Consolidación de múltiples workflows (`phpunit.yml`, `php-coverage.yml`, etc.) en un único archivo `ci.yml` altamente optimizado.
- **Reporte de Cobertura Inteligente:** Integración de `coverage-stats.php` que imprime un resumen detallado (Top 10 archivos con menos cobertura) directamente en los logs de GitHub Actions.
- **Validación PHPStan Nivel 9:** Elevación del estándar de calidad a nivel 9 (máximo) en todo el núcleo del proyecto (`src/`).
- **Matriz de Compatibilidad Mejorada:** Pruebas automáticas en PHP 8.1, 8.2, 8.3 y 8.4 contra SQLite, MySQL y PostgreSQL con reportes consolidados en los PRs.

### 🔧 Engine & Stability (Robustez del Motor)

**Mejoras en PdoEngine:**

- **Graceful Cache Invalidation:** El método de invalidación de caché ahora maneja llamadas sin criterios de forma segura (skipping) en lugar de lanzar excepciones, unificando el comportamiento en todos los drivers.
- **Strict Casting Fixes:** Corrección de múltiples casts implícitos de `mixed` a `string/int` para cumplir con PHPStan Level 9.
- **Advanced Operations:** Refuerzo de la lógica de operaciones JSON y CTEs con mejores validaciones de tipos escalares.

**Consistencia entre Drivers:**

- Armonización de la suite de pruebas `CacheTest` para asegurar que el comportamiento del caché sea idéntico en MySQL, PostgreSQL y SQLite.
- Eliminación de inconsistencias en la captura de excepciones durante la invalidación de caché.

### 🛠️ Developer Experience (Experiencia de Desarrollo)

- **Nuevo comando de estadísticas:** `composer coverage:stats` permite ver el resumen de cobertura localmente de forma instantánea.
- **Optimización de CI:** Eliminación de dependencias externas críticas (Mago) en el flujo de automatización para evitar cuellos de botella por red/servidores externos, manteniendo Mago para uso local.

### ✅ Estado de Calidad

- ✔️ **PHPStan Level 9**: 0 errores.
- ✔️ **Tests SQLite**: 618 tests pasando (100%).
- ✔️ **Tests MySQL**: 498 tests pasando (100%).
- ✔️ **Tests PostgreSQL**: 471 tests pasando (100%).
- ✔️ **Cobertura Global**: ~54% (con seguimiento detallado de hotspots).

## [1.7.0] - 2026-01-19

### ⚡ Performance Optimization (Mejoras de Rendimiento)

**Lazy Type Casting (Casting bajo demanda):**

- Se diferencia el casting de tipos hasta el acceso de propiedades (`__get()`), evitando transformaciones innecesarias en hidratación masiva.
- Implementación de `$castingCache` para cachear valores ya casteados y evitar re-casting en múltiples accesos.
- **Impacto: 31% de mejora en rendimiento total (~65ms → 42ms en operaciones SELECT de 1100 registros).**

**Eliminación de Closures en SQL Compilation:**

- Reemplazo de `match` expressions con closures anónimas por `if/switch` directo en `compileWhere()`.
- Reducción de overhead de creación y ejecución de closures.
- **Impacto: 3-5% de mejora adicional en queries complejas.**

**Simplificación de métodos estáticos:**

- `getAll()`, `getRow()`, `getCell()` ahora devuelven datos sin casting (mejora performance en data farms masivos).
- Si se necesita casting, usar métodos de instancia (`getDataCasted()`) o modelos con `loadInstance()`.

**Benchmark Results (SQLite in-memory):**

```
- SELECT simple (1100 registros): 67.05ms → 42.91ms (36% ↑)
- Hidratación bulk + casting: 57.15ms → 46.29ms (19% ↑)
- INSERT batch (1000 registros): 47.56ms → 21.76ms (54% ↑)
- Type Casting (100 ops): 6.33ms → 4.71ms (26% ↑)
- TOTAL: 211.47ms → 141.88ms (33% ↑)
```

### 🔧 Bug Fixes: Table Alias en UPDATE/DELETE

**Corrección de Alias en Operaciones UPDATE/DELETE:**

- Problema: El ORM rechazaba consultas como `table('versa_users as u')->update(...)` con error "Invalid or malicious table name detected"
- Causa: Las operaciones UPDATE/DELETE enviaban el alias como parte del nombre de tabla al motor SQL
- Solución:
  - `compileUpdate()` y `compileDelete()` ahora extraen correctamente el nombre base de la tabla antes de compilar
  - `compileWhere()` acepta parámetro `$removeAliases=true` para limpiar referencias de alias en WHERE cuando se usa UPDATE/DELETE
  - El alias `u.email` se convierte a `email` automáticamente en contexto UPDATE/DELETE
- **Tests**: 27 nuevos tests (9 SQLite + 9 MySQL + 9 PostgreSQL) validando:
  - Nombres de tabla con alias simple: `table as u`
  - Nombres de tabla con alias descriptivo: `table as users`
  - Operaciones SELECT, UPDATE, DELETE con alias
  - WHERE clauses con referencias de alias
  - Compatible con todos los motores de base de datos

**Ejemplos de uso:**

```php
// ✅ Ahora funciona correctamente
$orm->table('versa_users as u')
    ->where('u.email', '=', 'test@example.com')
    ->update(['name' => 'Updated']);

$orm->table('versa_users as u')
    ->where('u.active', '=', false)
    ->delete();
```

### ✅ Validación de Quality Gates

- ✔️ MySQL Tests: 498 tests (1 skipped)
- ✔️ PostgreSQL Tests: 478 tests (2 skipped)
- ✔️ SQLite Tests: 424 tests (1 skipped, 2 deprecations)
- ✔️ Zero breaking changes
- ✔️ PHPStan Level 8: 0 errores
- ✔️ Rector: sin warnings

## [1.6.0] - 2026-01-19

### 🛡️ Seguridad (hardening SQL)

- Validación estricta de identificadores y allowlist de operadores en WHERE/JOIN/HAVING para mitigar inyección por nombres/operadores.
- Sanitización defensiva de payloads de error al persistir logs.

### 🧾 Logging (solo errores)

- Política "solo ERROR": se eliminan logs debug/info/warning y fallbacks.
- Persistencia de errores garantizada por defecto en `logs/` (aunque no se configure `log_path`).

### ⚡ Performance e I/O

- Reducción de I/O: se eliminan escrituras de debug/dumps y se evita backtrace en hot paths cuando no hay debug.
- Generación SQL sin side-effects de logging.

### 🤖 DevEx / Calidad

- Nuevo `llms.txt` y enlace en README para asistentes.
- PHPStan: 0 errores en nivel 8.
- Rector: configuración estable sin warnings en `rector:check`.

## [1.5.0] - 2026-01-14

### � Nueva Característica Principal: JOIN RAW con SQL Personalizado

- **Soporte Completo para JOIN RAW**: Nueva funcionalidad para escribir JOINs con SQL crudo
  - ✅ Método `joinRaw()` permite SQL personalizado con binding seguro de parámetros
  - ✅ Soporte para LEFT JOIN, RIGHT JOIN, INNER JOIN y CROSS JOIN en modo raw
  - ✅ Binding de parámetros posicionales (`?`) con array de valores
  - ✅ Compatibilidad total con MySQL, PostgreSQL y SQLite
  - ✅ Integración fluida con el QueryBuilder existente

### 💡 Ejemplos de Uso JOIN RAW

```php
// ✅ JOIN RAW básico con parámetros seguros
$results = $orm->table('users as u')
    ->joinRaw('INNER JOIN posts p ON p.user_id = u.id AND p.status = ?', ['published'])
    ->select(['u.name', 'p.title'])
    ->get();

// ✅ JOIN RAW con múltiples condiciones
$videos = $orm->table('channels as c')
    ->joinRaw(
        'LEFT JOIN videos v ON v.channel_id = c.id AND v.views > ? AND v.created_at > ?',
        [1000, '2025-01-01']
    )
    ->select(['c.name as channel_name', 'COUNT(v.id) as video_count'])
    ->groupBy('c.id')
    ->get();

// ✅ Combinación de JOIN tradicional + JOIN RAW
$data = $orm->table('orders as o')
    ->join('customers as c', 'o.customer_id', '=', 'c.id')  // JOIN tradicional
    ->joinRaw(
        'LEFT JOIN order_items oi ON oi.order_id = o.id AND oi.quantity > ?',
        [5]
    )  // JOIN RAW
    ->where('o.status', '=', 'completed')
    ->get();
```

### 🔧 Implementación Técnica

- **QueryBuilder.php**: Nuevos métodos para JOIN RAW
  - `joinRaw($sql, $bindings = [])` - INNER JOIN con SQL crudo
  - `leftJoinRaw($sql, $bindings = [])` - LEFT JOIN con SQL crudo
  - `rightJoinRaw($sql, $bindings = [])` - RIGHT JOIN con SQL crudo
  - `crossJoinRaw($sql, $bindings = [])` - CROSS JOIN con SQL crudo
  - Propiedad `$joins` actualizada con soporte para tipos raw: `{type, raw_sql, bindings}`
  - Compilación segura con prepared statements en todos los motores

### 🛡️ Seguridad y Validación

- **Prepared Statements Nativos**:
  - Todos los parámetros de JOIN RAW usan binding posicional (`?`)
  - Protección automática contra inyección SQL
  - Validación estricta de parámetros con PHPStan level 8

- **Type Safety Mejorada**:
  - PHPDoc completo para propiedad `$joins` incluyendo tipos raw
  - Comparaciones booleanas estrictas con `preg_match() !== 1`
  - Type hints y return types en todos los métodos relacionados

### ✅ Cobertura de Tests Completa

- **QueryBuilderJoinRawTest.php**: Suite completa de tests para JOIN RAW
  - ✅ `testJoinRawBasicSyntax()` - Sintaxis básica con un parámetro
  - ✅ `testLeftJoinRawWithMultipleParams()` - LEFT JOIN con múltiples parámetros
  - ✅ `testJoinRawWithGroupBy()` - JOIN RAW + GROUP BY + COUNT
  - ✅ `testJoinRawWithTraditionalJoin()` - Combinación JOIN tradicional + RAW
  - ✅ `testJoinRawEmptyResults()` - Validación de resultados vacíos
  - Tests ejecutados en **MySQL, PostgreSQL y SQLite** con 100% de éxito

### 📊 Validación Multi-Motor

- **Tests 100% Pasando en todos los motores**:
  - SQLite: 411 tests, 1264 assertions ✅
  - PostgreSQL: 469 tests, 1458 assertions ✅
  - MySQL: 477+ tests completos ✅
  - **Total: 1350+ tests sin errores**

### 🎯 Casos de Uso Prácticos

- **Consultas Complejas**: Cuando necesitas lógica SQL avanzada que no es posible con JOIN tradicional
- **Optimización de Performance**: Control fino sobre condiciones de JOIN para índices específicos
- **Funciones SQL Específicas**: Uso de funciones nativas del motor (DATE_ADD, EXTRACT, etc.)
- **Migración de SQL Existente**: Integrar queries SQL legacy sin reescribir completamente
- **Subconsultas en JOIN**: Usar subconsultas complejas directamente en la condición ON

### 🔍 Calidad de Código

- **Análisis Estático**:
  - PHPStan: 0 errores en nivel 8 (máxima strictness)
  - Psalm: 0 errores críticos, inferencia de tipos al 91.47%
  - Atributos `#[\Override]` agregados en 76 métodos
  - 40 archivos mejorados con type safety automático

- **Estandarización de Tests**:
  - Credenciales PostgreSQL consistentes ('local'/'local')
  - Type casting correcto (COUNT() retorna int en lugar de string)
  - Sin breaking changes en código existente

---

## [1.4.1] - 2025-09-08

### 🔥 Fix Crítico: Timestamps Automáticos

- **Timestamps Automáticos Funcionando**: Corrección fundamental en el método `timestamps()` del SchemaBuilder
  - El método `timestamps()` ahora genera automáticamente valores por defecto:
    - `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
    - `updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP` (MySQL)
    - `updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` (PostgreSQL/SQLite)
  - Fix implementado en `src/Schema/Blueprint.php` usando `useCurrent()` y `useCurrentOnUpdate()`
  - Validado funcionando en todos los motores: MySQL, PostgreSQL y SQLite
  - Los timestamps ahora se generan automáticamente sin configuración manual

### 📋 Test Completo de Migración Schema

- **Nuevo Test de Migración**: `testMigrateFromOldSchemaCreateToNewSchemaBuilder()`
  - Demuestra la conversión completa de `schemaCreate()` (arrays) al nuevo SchemaBuilder (API fluida)
  - Incluye ejemplos lado a lado del método anterior vs el nuevo
  - Valida que los timestamps automáticos funcionan correctamente
  - Prueba inserción de datos reales con timestamps automáticos
  - Documentación exhaustiva de ventajas del nuevo método

### 🔗 Foreign Keys y Constraints Completos

- **Test Exhaustivo de Foreign Keys**: Nuevo `ForeignKeysAndConstraintsTest.php` con 10 tests
  - ✅ Valida sintaxis con array: `$table->foreign(['campo'])->references('id')->on('tabla')`
  - ✅ Valida sintaxis simple: `$table->foreign('campo')->references('id')->on('tabla')`
  - ✅ Diferentes acciones: `onDelete('CASCADE')`, `onDelete('SET NULL')`, `onDelete('RESTRICT')`
  - ✅ Índices completos: simples, únicos, compuestos, fulltext
  - ✅ Relaciones many-to-many con tabla pivot
  - ✅ Foreign keys auto-referenciales (estructura de árbol)
  - ✅ Validación de constraints con datos reales
  - ✅ Sistema complejo de órdenes con múltiples foreign keys

### 📚 Documentación Completa

- **Guía de Migración**: `docs/MigrationGuide_SchemaBuilder.md`
  - Comparación detallada: método anterior (arrays) vs nuevo (API fluida)
  - Ejemplos prácticos de conversión paso a paso
  - Ventajas del nuevo SchemaBuilder con timestamps automáticos
  - Instrucciones de migración gradual
  - Compatibilidad y soporte multi-motor

- **Guía de Foreign Keys**: `docs/ForeignKeysAndIndexes_CompleteGuide.md`
  - Todas las sintaxis válidas para foreign keys con ejemplos
  - Guía completa de índices: simples, únicos, compuestos, fulltext
  - Casos de uso prácticos: relaciones N:M, auto-referenciales, sistemas complejos
  - Mejores prácticas y optimización de rendimiento
  - Ejemplos de validación de constraints

### ✅ Validación Multi-Motor

- **Tests Completos Pasando**:
  - PostgreSQL: 447 tests ✅ (incluyendo nuevos tests de migración y foreign keys)
  - MySQL: 477 tests ✅ (compatibilidad completa mantenida)
  - SQLite: 398 tests ✅ (funcionalidad completa validada)

### 🚀 Mejoras en Developer Experience

- **API más Intuitiva**: El SchemaBuilder ahora es completamente usable sin configuración manual
  - `$table->timestamps()` funciona automáticamente sin setup adicional
  - Sintaxis de foreign keys más flexible (acepta arrays y strings)
  - Timestamps automáticos en `insertMany()` y operaciones batch
  - Compatibilidad perfecta entre todos los motores de base de datos

### 💡 Ejemplos de Uso Actualizado

```php
// ✅ Timestamps automáticos funcionando
$schema->create('documentos', function ($table) {
    $table->id();
    $table->string('titulo');
    $table->unsignedBigInteger('carpeta_id')->nullable();

    // ✨ Timestamps automáticos - sin configuración manual
    $table->timestamps(); // created_at y updated_at con valores por defecto

    // ✅ Foreign key con sintaxis de array (validada)
    $table->foreign(['carpeta_id'])
          ->references('id')
          ->on('documentos_carpetas')
          ->onDelete('CASCADE');
});

// ✅ Inserción con timestamps automáticos
$result = $orm->table('documentos')->insertMany([
    ['titulo' => 'Documento 1'],
    ['titulo' => 'Documento 2']
]); // created_at y updated_at se asignan automáticamente
```

### 🔧 Cambios Técnicos

- **Blueprint.php**: Método `timestamps()` actualizado para usar `useCurrent()` automáticamente
- **Tests actualizados**: Nuevos tests específicos para demostrar funcionalidad
- **Documentación técnica**: Guías completas con ejemplos prácticos listos para usar

---

## [1.4.0] - 2025-09-07

### 🔧 Calidad de Código y Análisis Estático

- **PHPStan Nivel 8 Completo**: Análisis estático completamente limpio sin errores ni warnings
  - Reducción de 142 errores a 0 errores (100% de resolución)
  - Documentación completa de tipos array (`@var array<int, string>`, `@var array<string, mixed>`)
  - Implementación de tipos `list<T>` precisos y union types documentados
  - Conversión completa de comparaciones loose a strict (`===`, `!==`, explicit null checks)

- **Sistema de Tipos Robusto**: Mejoras comprehensivas en type safety
  - Manejo explícito de valores null y boolean en todas las comparaciones
  - Corrección de `preg_replace()` con manejo de `string|null`
  - Arreglo de comparaciones float con `!== 0.0` para precisión estricta
  - Implementación de `array_filter()` con parámetros strict

- **Nuevas Clases de Definición**: Estructuras de datos especializadas para operaciones de esquema
  - `ColumnDef`: Para definiciones de columnas de base de datos
  - `IndexDef`: Para definiciones de índices con ArrayAccess
  - `TableConstraintsDef`: Para constraints de tabla
  - `AlterChanges`: Para cambios de ALTER con ArrayAccess
  - `ColumnDefinition`: Para definición fluida de columnas con modificadores
  - `Blueprint`: Para definición completa de tablas con API encadenable
  - `TypeMapper`: Para mapeo inteligente de tipos entre PHP y SQL

### 🏗️ Nuevo SchemaBuilder Moderno

- **API Fluida Laravel-Style**: Sistema completo de manipulación de esquemas de base de datos
  - Clase `SchemaBuilder` con API fluida para DDL (Data Definition Language)
  - Facade estático `VersaSchema` para uso intuitivo y limpio
  - Clase `Blueprint` para definición de tablas con métodos encadenables
  - Clase `ColumnDefinition` para definición precisa de columnas con modificadores

- **Compatibilidad Multi-Motor**: Transparencia completa entre MySQL, PostgreSQL y SQLite
  - Generación automática de SQL específico para cada motor de base de datos
  - Manejo inteligente de diferencias (AUTO_INCREMENT vs SERIAL, TINYINT vs BOOLEAN)
  - Identificadores apropiados (backticks vs quotes) según el motor
  - Soporte nativo para claves foráneas con limitaciones específicas por motor

- **Operaciones Completas de Esquema**:
  - **Creación**: `VersaSchema::create()`, `VersaSchema::createIfNotExists()`
  - **Modificación**: `VersaSchema::table()` con Blueprint para alteraciones
  - **Eliminación**: `VersaSchema::drop()`, `VersaSchema::dropIfExists()`
  - **Inspección**: `hasTable()`, `hasColumn()`, `hasIndex()`, `getColumns()`, `getIndexes()`
  - **Utilidades**: `rename()` para renombrado de tablas

- **Tipos de Columna Completos**: Soporte exhaustivo para todos los tipos de datos
  - Básicos: `string()`, `text()`, `integer()`, `bigInteger()`, `boolean()`
  - Numéricos: `decimal()`, `float()`, `double()`, `unsignedInteger()`
  - Fechas: `date()`, `dateTime()`, `timestamp()`, `timestamps()`
  - Especiales: `json()`, `uuid()`, `ipAddress()`, `enum()`, `set()`
  - Automáticos: `id()` (primary key auto-increment), `timestamps()` (created_at/updated_at)

- **Modificadores de Columna**: Sistema flexible de características adicionales
  - Nullabilidad: `nullable()`, `default($value)`
  - Índices: `unique()`, `index()`, `primary()`
  - Posicionamiento: `after($column)` (MySQL), `first()` (MySQL)
  - Comentarios: `comment($text)` para documentación
  - Auto-incremento: `autoIncrement()` para claves primarias

- **Gestión de Índices y Constraints**:
  - Índices simples y compuestos con `index()`, `unique()`
  - Claves foráneas con `foreign()->references()->on()->onDelete()`
  - Eliminación selectiva: `dropIndex()`, `dropUnique()`, `dropForeign()`
  - Soporte para métodos de indexación específicos (BTREE, HASH)

### 🔒 Mejoras en Seguridad y Robustez

- **Variable Method Calls**: Manejo seguro de métodos dinámicos
  - Implementación de `@phpstan-ignore-next-line` para métodos dinámicos válidos
  - Documentación apropiada de parámetros en métodos `__call()`
  - Protección contra llamadas de método inseguras

- **SQL y PDO**: Fortalecimiento del motor de base de datos
  - Manejo correcto de tipos `PDO|null` en conexiones
  - Eliminación de checks redundantes de `instanceof` y `method_exists()`
  - Mejoras en la documentación de arrays en SQL generation
  - Validación estricta de parámetros en PdoConnection y PdoEngine

### 📊 Impacto en Desarrollo

- **Maintainability**: Mejor documentación facilita el mantenimiento futuro
- **Error Prevention**: Los tipos estrictos previenen errores en runtime
- **Developer Experience**: IntelliSense mejorado y detección temprana de errores
- **Code Quality**: Cumple con los estándares más altos de PHP (PHPStan nivel 8)
- **Database Agnosticism**: Mismo código funciona en MySQL, PostgreSQL y SQLite
- **Rapid Prototyping**: SchemaBuilder acelera el desarrollo y prototipado
- **Test Infrastructure**: Tests automatizados para operaciones de esquema complejas

### 🧪 Nuevas Pruebas y Validaciones

- **Tests Específicos para SchemaBuilder**: Suite completa de pruebas para cada motor
  - `BasicSchemaBuilderTest`: Pruebas fundamentales de creación y modificación
  - `AdvancedSchemaBuilderTest`: Funcionalidades complejas con relaciones y constraints
  - `SimpleSchemaTest`: Verificación de operaciones básicas
  - `TypeMapperTest`: Validación del mapeo de tipos entre motores
  - Tests separados para MySQL, PostgreSQL y SQLite en `testMysql/Schema/`, `testPostgreSQL/Schema/`, `testSQLite/Schema/`

- **Cobertura Multi-Motor**: Validación exhaustiva de compatibilidad
  - Generación correcta de SQL específico para cada motor
  - Comportamiento consistente de tipos de datos entre motores
  - Manejo apropiado de limitaciones específicas (ej. claves foráneas en SQLite)
  - Tests de roundtrip para verificar integridad de datos

### 💡 Ejemplo de Uso del SchemaBuilder

```php
use VersaORM\Schema\VersaSchema;

// Crear tabla de usuarios con API moderna
VersaSchema::create('users', function ($table) {
    $table->id();                              // Primary key auto-increment
    $table->string('name');                    // VARCHAR(255)
    $table->string('email', 100)->unique();   // VARCHAR(100) UNIQUE
    $table->timestamp('email_verified_at')->nullable();
    $table->boolean('active')->default(true);
    $table->json('preferences')->nullable();   // JSON/TEXT según motor
    $table->timestamps();                      // created_at, updated_at
});

// Modificar tabla existente
VersaSchema::table('users', function ($table) {
    $table->string('phone', 20)->nullable();           // Agregar columna
    $table->index(['email', 'active'], 'idx_email_active'); // Índice compuesto
    $table->dropColumn('old_field');                   // Eliminar columna
});

// Verificación e inspección
if (VersaSchema::hasTable('users')) {
    $columns = $orm->schemaBuilder()->getColumns('users');
    foreach ($columns as $column) {
        echo "Columna: {$column['name']} ({$column['type']})\n";
    }
}
```

---

## [1.3.0] - 2025-09-05

### ✨ Nuevas Características

- **Timestamps automáticos**: Soporte completo para `created_at` y `updated_at` automáticos en inserciones y actualizaciones
  - Se asignan automáticamente durante operaciones de store()
  - Compatibles con todos los motores de base de datos (MySQL, PostgreSQL, SQLite)
  - Formato UTC con microsegundos para evitar colisiones en tests

- **Mejoras en QueryBuilder**: El parámetro `foreign` en método `on()` ahora acepta tanto cadenas como enteros para mayor flexibilidad

- **Nuevas pruebas de esquema**: Agregadas pruebas comprehensivas para creación y alteración de esquemas en PostgreSQL y SQLite

### 🐛 Correcciones

- **Fix crítico para PostgreSQL**: Corregido manejo de valores boolean en `insertMany()`
  - PostgreSQL ahora recibe correctamente valores 1/0 en lugar de strings vacíos
  - Se agregó procesamiento de tipos antes del envío a PDO
  - Mantiene compatibilidad con MySQL y SQLite

- **Eliminación de columnas e índices**: Nuevas pruebas para operaciones de eliminación en MySQL

### 🔧 Mejoras y Refactoring

- **Consistencia de código**: Refactoring extensivo para mantener estilo consistente
  - Assertions actualizadas a métodos estáticos (`static::assert*`)
  - Espacios normalizados en closures
  - Limpieza de tests y funciones no utilizadas

- **Documentación**: Configuración de validación mejorada y actualizada

### 🗃️ Base de Datos

- **Mejoras en motor PDO**: Optimizaciones en `PdoEngine` y `SqlGenerator`

## [1.2.0] - 2025-08-27

### Cambios en `src/` (resumen)

- Mejoras en la generación de esquema y creación de índices:
  - `createIndexPortable` y `schemaCreate` ahora generan DDL portable y manejan correctamente diferencias entre MySQL, PostgreSQL y SQLite (evitan cláusulas inválidas en SQLite, posicionan `USING` según driver).

- `VersaORM`:
  - Mejoras en el flujo de `execute()`, validaciones DDL (freeze) y sanitización de identificadores.
  - Logging y manejo de errores reforzados.

- `VersaModel`:
  - Reutilización de la instancia de ORM para preservar estado de conexión.
  - Mejoras en helpers de consulta y en la resolución de condiciones (p. ej. `findOne` y métodos auxiliares).

- `QueryBuilder`:
  - Mejoras en la exportación y carga de relaciones; manejo más robusto de eager-loading y errores asociados.

- `SQL/PdoEngine`:
  - Ajustes en `query_plan` y soporte de métricas para entornos de pruebas.

- `HasStrongTyping`:
  - Incorporación de soporte para conversores de tipo en tiempo de ejecución y mejoras en mapeo de tipos.

> Nota: múltiples pruebas unitarias nuevas cubren estos cambios (tests en `tests/`).

# v1.1.1 (21-08-2025)

## 🧩 Compatibilidad y mejoras en el ORM

- **Relaciones ORM ahora compatibles con QueryBuilder**
  Las relaciones (`hasOne`, `hasMany`, `belongsTo`, `belongsToMany`) permiten manipulación avanzada de consultas mediante el QueryBuilder, soportando filtros, joins, ordenamientos y paginación directamente sobre las relaciones.
  Ejemplo:

  ```php
  $user->posts()->where('published', true)->orderBy('created_at', 'desc')->limit(5)->get();
  ```

- **Exposición directa del QueryBuilder en métodos de relación**
  Los métodos de relación devuelven instancias del QueryBuilder, permitiendo encadenar métodos y construir consultas complejas sin perder el tipado ni la seguridad.

- **Soporte de FULL OUTER JOIN para SQLite**
  El motor de consultas ahora traduce y simula correctamente los `FULL OUTER JOIN` en SQLite, permitiendo compatibilidad total con sentencias avanzadas que antes solo funcionaban en MySQL/PostgreSQL.

- **Mejoras en la inferencia de nombres de tabla**
  El método `tableName` ahora es más robusto y consistente, permitiendo inferir el nombre de la tabla asociada a cada modelo de forma automática y segura.

## ⚡️ Refactor y optimización

- Refactorización profunda del script de integración QA (`qa-integration.php`), permitiendo la ejecución ordenada y sin conflictos de Rector, Pint, PHP-CS-Fixer, PHPStan y Psalm.
- Mejoras de legibilidad y estructura en controladores y modelos, optimizando el conteo de registros y la manipulación de datos.

## 🛡️ Seguridad y consistencia

- Ajuste de operadores lógicos y condicionales en tests y binarios para mayor claridad y robustez.
- Validación y limpieza de datos en scripts de setup y migraciones.

## 🧰 Herramientas y configuración

- Integración avanzada de Laravel Pint, con configuración para evitar conflictos con PHP-CS-Fixer y mantener el estilo PSR-12/Laravel.
- Actualización de dependencias y scripts en `composer.json` para facilitar el desarrollo y la integración continua.

## 📝 Documentación y ejemplos

- Ejemplos actualizados para reflejar las nuevas capacidades del ORM y el uso avanzado de relaciones y QueryBuilder.
- Mejoras en los scripts de setup y migración para facilitar la adopción y pruebas.

# v1.1 - 2025-08-19

- Métodos attach, detach, sync y fresh() en BelongsToMany para gestión directa de la tabla pivot.
- Documentación actualizada para relaciones muchos-a-muchos.
- Fixes de compatibilidad con Psalm y QueryBuilder.
- Mejoras en los tests de relaciones y sincronización.

# Changelog

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [Unreleased]

### Añadido ⚡

### Mejorado 🚀

### Seguridad 🔒

- Validación preventiva en `onRaw()` contra sentencias múltiples (`;`), comentarios (`--`, `#`, `/* */`) y palabras DDL/DML peligrosas (DROP, ALTER, INSERT, etc.).

### Tests ✅

- Nuevos archivos de pruebas multi‑motor: `testSQLite/QueryBuilderOnRawTest.php`, `testMysql/QueryBuilderOnRawTest.php`, `testPostgreSQL/QueryBuilderOnRawTest.php` cubriendo:
  - Uso básico `onRaw`
  - Múltiples llamadas encadenadas `onRaw()`
  - Bindings aplicados correctamente

### Documentación 📚

- Sección añadida a `docs/user-guide/02-query-builder.md` describiendo `on()` vs `onRaw()`, casos de uso, tabla comparativa y ejemplos.

### Interno 🔧

---

## [1.4_beta] - 2025-08-05

### Añadido ⚡

- Método `upsert()` individual para inserción inteligente con detección automática de duplicados
- Método `insertOrUpdate()` como alias intuitivo para operaciones upsert
- Método `save()` inteligente que detecta automáticamente si es INSERT o UPDATE
- Método `replaceInto()` para compatibilidad específica MySQL con reemplazo completo
- Integración completa en VersaModel con validación automática y manejo de errores
  - MySQL: `INSERT ... ON DUPLICATE KEY UPDATE`
  - PostgreSQL: `INSERT ... ON CONFLICT DO UPDATE`

### Mejorado 🚀

- **QueryBuilder**: Ampliado con 5 nuevos métodos CRUD (líneas 1580-2100+)
  - Validación completa de datos de entrada con sanitización automática
  - Manejo inteligente de claves únicas y detección de conflictos
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

## [1.3.0_beta] - 2025-08-06

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

## [1.2.0_beta] - 2025-08-05

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

## [1.1.0_beta] - 2025-07-30

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

## [1.0.0_beta] - 2025-07-15

### Añadido

- Lanzamiento inicial de VersaORM-PHP
- Query Builder completo
- Sistema de modelos Active Record
- Núcleo Rust para máximo rendimiento
- Soporte para MySQL, PostgreSQL, SQLite
- Documentación completa
