# 📊 Análisis del Estado Actual de VersaORM-PHP

## 🔍 RESUMEN EJECUTIVO

**ACTUALIZACIÓN: 20 de agosto de 2025**

Este análisis refleja el estado actual del proyecto VersaORM-PHP, basado en una revisión exhaustiva del código fuente en el directorio `src`. El ORM ha alcanzado una madurez significativa, con un robusto conjunto de características centradas en el motor PDO de PHP, y una API fluida y completa a través de sus componentes principales: `VersaORM`, `QueryBuilder` y `VersaModel`.

La arquitectura actual prioriza la estabilidad, la seguridad y una experiencia de desarrollador intuitiva, ofreciendo funcionalidades avanzadas como operaciones batch, un sistema de relaciones completo, tipado fuerte, y un modo "freeze" para proteger el esquema en producción.

---

## ⚙️ Análisis Detallado de Métodos por Clase

A continuación se presenta un listado completo de los métodos públicos disponibles en las clases principales del ORM, extraídos directamente del código fuente.

### 1. Clase `VersaORM` (`src/VersaORM.php`)

Clase principal que actúa como fachada del ORM. Gestiona la configuración, la conexión y la ejecución de operaciones a bajo nivel.

**Métodos de Configuración y Conexión:**
- `__construct(array $config)`: Inicializa el ORM con la configuración de la base de datos.
- `setConfig(array $config)`: Establece o modifica la configuración de la instancia.
- `getConfig(): array`: Obtiene la configuración actual.
- `disconnect(): void`: Cierra la conexión con la base de datos.
- `version(): string`: Devuelve la versión actual del ORM.

**Métodos de Ejecución de Consultas:**
- `table(string $table, ?string $modelClass = null): QueryBuilder`: Inicia un nuevo constructor de consultas (`QueryBuilder`) para una tabla específica.
- `exec(string $query, array $bindings = []): mixed`: Ejecuta una consulta SQL cruda y devuelve los resultados.
- `raw(string $query, array $bindings = []): mixed`: Alias de `exec()`.
- `executeQuery(string $action, array $params): mixed`: Método público para que `QueryBuilder` ejecute consultas estructuradas.

**Gestión de Esquema (DDL):**
- `schema(string $subject, ?string $tableName = null): mixed`: Obtiene información del esquema de la base de datos.
- `schemaCreate(string $table, array $columns, array $options = []): void`: Crea una nueva tabla en la base de datos.
- `schemaAlter(string $table, array $changes): void`: Modifica una tabla existente (añadir, eliminar, renombrar columnas, etc.).
- `schemaDrop(string $table, bool $ifExists = true): void`: Elimina una tabla de la base de datos.
- `schemaRename(string $from, string $to): void`: Renombra una tabla.

**Transacciones:**
- `beginTransaction(): void`: Inicia una transacción.
- `commit(): void`: Confirma los cambios de la transacción actual.
- `rollBack(): void`: Revierte los cambios de la transacción actual.

**Seguridad (Modo Freeze):**
- `freeze(bool $frozen = true): self`: Activa o desactiva el modo "freeze" global para prevenir cambios en el esquema.
- `isFrozen(): bool`: Verifica si el modo "freeze" global está activo.
- `freezeModel(string $modelClass, bool $frozen = true): self`: Activa o desactiva el modo "freeze" para un modelo específico.
- `isModelFrozen(string $modelClass): bool`: Verifica si un modelo específico está congelado.
- `validateFreezeOperation(string $operation, ?string $modelClass = null, array $context = []): void`: Valida si una operación DDL está permitida según el estado de "freeze".

**Caché y Métricas:**
- `cache(string $action, array $params = []): array`: Administra el caché interno del ORM.
- `metrics(): ?array`: Devuelve métricas de rendimiento del motor PDO.
- `metricsReset(): void`: Reinicia las métricas de rendimiento.

---

### 2. Clase `QueryBuilder` (`src/QueryBuilder.php`)

El corazón del ORM para la construcción de consultas SQL de manera fluida y programática.

**Métodos de Construcción de Consultas (SELECT):**
- `from(string $table): self`: Especifica la tabla principal de la consulta.
- `select(array $columns = ['*']): self`: Define las columnas a seleccionar.
- `selectRaw(string $expression, array $bindings = []): self`: Añade una expresión SQL cruda al `SELECT`.
- `selectSubQuery(Closure|QueryBuilder $callback, string $alias): self`: Añade una subconsulta al `SELECT`.

**Cláusulas WHERE:**
- `where(string $column, string $operator, mixed $value): self`: Añade una condición `WHERE`.
- `orWhere(string $column, string $operator, mixed $value): self`: Añade una condición `OR WHERE`.
- `whereIn(string $column, array $values): self`: Añade una condición `WHERE IN`.
- `whereNotIn(string $column, array $values): self`: Añade una condición `WHERE NOT IN`.
- `whereNull(string $column): self`: Añade una condición `WHERE IS NULL`.
- `whereNotNull(string $column): self`: Añade una condición `WHERE IS NOT NULL`.
- `whereBetween(string $column, mixed $min, mixed $max): self`: Añade una condición `WHERE BETWEEN`.
- `whereNotBetween(string $column, mixed $min, mixed $max): self`: Añade una condición `WHERE NOT BETWEEN`.
- `whereRaw(string $sql, array $bindings = []): self`: Añade una condición `WHERE` con SQL crudo.
- `whereSubQuery(string $column, string $operator, $callback): self`: Añade una subconsulta en una cláusula `WHERE`.
- `whereExists($callback): self`: Añade una subconsulta `WHERE EXISTS`.
- `whereNotExists($callback): self`: Añade una subconsulta `WHERE NOT EXISTS`.

**Cláusulas JOIN:**
- `join(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self`: Añade un `INNER JOIN`.
- `leftJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self`: Añade un `LEFT JOIN`.
- `rightJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self`: Añade un `RIGHT JOIN`.
- `fullOuterJoin(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self`: Añade un `FULL OUTER JOIN`.
- `crossJoin(string $table): self`: Añade un `CROSS JOIN`.
- `naturalJoin(string $table): self`: Añade un `NATURAL JOIN`.
- `joinSub($subquery, string $alias, string $firstCol, string $operator, string $secondCol): self`: Añade un `JOIN` con una subconsulta.
- `on(string $local, string $operator, string $foreign, string $boolean = 'AND'): self`: Añade una condición `ON` a un `JOIN`.
- `onRaw(string $expression, array $bindings = [], string $boolean = 'AND'): self`: Añade una condición `ON` cruda a un `JOIN`.

**Agrupación y Ordenación:**
- `groupBy(array|string $columns): self`: Agrupa los resultados.
- `groupByRaw(string $expression, array $bindings = []): self`: Agrupa los resultados con una expresión cruda.
- `having(string $column, string $operator, mixed $value): self`: Añade una cláusula `HAVING`.
- `orderBy(string $column, string $direction = 'asc'): self`: Ordena los resultados.
- `orderByRaw(string $expression, array $bindings = []): self`: Ordena los resultados con una expresión cruda.

**Paginación y Límites:**
- `limit(int|string $count): self`: Limita el número de resultados.
- `offset(int $count): self`: Especifica el desplazamiento inicial de los resultados.

**Relaciones (Eager Loading):**
- `with($relations): self`: Especifica las relaciones a cargar de forma anticipada.

**Métodos de Obtención de Resultados:**
- `findAll(): array`: Devuelve un array de objetos `VersaModel`.
- `findOne(): ?VersaModel`: Devuelve un único objeto `VersaModel` o `null`.
- `find(mixed $id, string $pk = 'id'): ?VersaModel`: Busca un registro por su clave primaria y devuelve un `VersaModel`.
- `first(): ?VersaModel`: Alias de `findOne()`.
- `get(): array`: Devuelve un array de arrays (ideal para APIs).
- `getAll(): array`: Alias de `get()`.
- `firstArray(): ?array`: Devuelve el primer registro como un array o `null`.
- `count(): int`: Devuelve el número de registros que coinciden con la consulta.
- `exists(): bool`: Verifica si existen registros que coincidan con la consulta.

**Operaciones de Escritura (CUD):**
- `insert(array $data): bool`: Inserta un nuevo registro.
- `insertGetId(array $data): ?int`: Inserta un registro y devuelve su ID.
- `update(array $data): self`: Actualiza registros que coinciden con las cláusulas `WHERE`.
- `delete(): ?VersaModel`: Elimina registros que coinciden con las cláusulas `WHERE`.

**Operaciones de Lote (Batch):**
- `insertMany(array $records, int $batchSize = 1000): array`: Inserta múltiples registros de forma optimizada.
- `updateMany(array $data, int $maxRecords = 10000): array`: Actualiza múltiples registros.
- `deleteMany(int $maxRecords = 10000): array`: Elimina múltiples registros.

**Operaciones UPSERT y REPLACE:**
- `upsert(array $data, array $uniqueKeys, array $updateColumns = []): array`: Realiza una operación `INSERT ... ON DUPLICATE KEY UPDATE`.
- `insertOrUpdate(array $data, array $uniqueKeys, array $updateColumns = []): array`: Verifica si un registro existe y lo actualiza, o lo crea si no.
- `save(array $data, string $primaryKey = 'id'): array`: Guarda un registro (decide automáticamente entre `INSERT` y `UPDATE`).
- `createOrUpdate(array $data, array $conditions, array $updateColumns = []): array`: Crea o actualiza un registro basado en condiciones personalizadas.
- `upsertMany(array $records, array $uniqueKeys, array $updateColumns = [], int $batchSize = 1000): array`: Realiza un `UPSERT` masivo.
- `replaceInto(array $data): array`: Realiza una operación `REPLACE INTO` (específico de MySQL).
- `replaceIntoMany(array $records, int $batchSize = 1000): array`: Realiza un `REPLACE INTO` masivo.

**Modo Lazy (Diferido):**
- `lazy(): self`: Activa el modo de ejecución diferida.
- `collect(): array`: Ejecuta las operaciones acumuladas en modo lazy.
- `chain(self $otherQuery): self`: Encadena otro `QueryBuilder` en modo lazy.
- `explain(): array`: Muestra el plan de ejecución de la consulta sin ejecutarla.

**Utilidades:**
- `dispense(): VersaModel`: Crea una nueva instancia de `VersaModel` vacía.
- `getTable(): string`: Obtiene el nombre de la tabla.
- `getModelInstance(): VersaModel`: Obtiene una instancia del modelo asociado.

---

### 3. Clase `VersaModel` (`src/VersaModel.php`)

Implementación del patrón `Active Record`. Cada instancia representa una fila de una tabla de la base de datos.

**Métodos Estáticos (Creación y Configuración):**
- `setORM(?VersaORM $orm): void`: Establece la instancia global del ORM para todos los modelos.
- `getGlobalORM(): ?VersaORM`: Obtiene la instancia global del ORM.
- `orm(): VersaORM`: Atajo para obtener la instancia global del ORM (lanza excepción si no está configurada).
- `db(): VersaORM`: Alias de `orm()`.
- `dispense(string $table): self`: Crea una nueva instancia de modelo vacía.
- `load(string $table, $id, string $pk = 'id'): ?self`: Carga un modelo desde la base de datos por su ID.
- `create(array $attributes): static`: Crea una nueva instancia y la rellena con atributos.
- `exportAll(array $models): array`: Exporta una colección de modelos a un array de arrays.
- `freeze(bool $frozen = true): void`: Activa/desactiva el modo "freeze" para este modelo.
- `isFrozen(): bool`: Verifica si el modelo está congelado.

**Métodos de Instancia (CRUD):**
- `fill(array $attributes): self`: Rellena el modelo con un array de atributos (respetando `fillable`/`guarded`).
- `store(): int|string|null`: Guarda el modelo en la base de datos (crea o actualiza).
- `storeAndGetId(): int|string|null`: Guarda el modelo y devuelve su ID.
- `update(array $attributes): self`: Actualiza el modelo con nuevos atributos y lo guarda.
- `trash(): void`: Elimina el registro de la base de datos.
- `loadInstance($data, string $pk = 'id'): self`: Carga datos en la instancia actual del modelo.
- `fresh(string $primaryKey = 'id'): static`: Recarga el modelo desde la base de datos en una nueva instancia.

**Operaciones UPSERT (Nivel de Modelo):**
- `upsert(array $uniqueKeys, array $updateColumns = []): array`: Realiza una operación `UPSERT` con los datos del modelo.
- `save(string $primaryKey = 'id'): array`: Guarda el modelo (decide entre `INSERT`/`UPDATE`).
- `insertOrUpdate(array $uniqueKeys, array $updateColumns = []): array`: `INSERT` o `UPDATE` basado en claves únicas.
- `createOrUpdate(array $conditions, array $updateColumns = []): array`: `INSERT` o `UPDATE` basado en condiciones personalizadas.
- `smartUpsert(?array $updateColumns = null): array`: Realiza un `UPSERT` detectando automáticamente las claves únicas del esquema.

**Atributos y Datos:**
- `__set(string $key, mixed $value): void`: Asigna un valor a un atributo.
- `__get(string $key): mixed`: Obtiene el valor de un atributo o una relación.
- `__isset(string $key): bool`: Verifica si un atributo está definido.
- `__unset(string $key): void`: Elimina un atributo.
- `export(): array`: Convierte el modelo y sus relaciones a un array.
- `getAttribute(string $key): mixed`: Obtiene el valor crudo de un atributo.
- `getData(): array`: Obtiene todos los atributos crudos del modelo.
- `getDataCasted(): array`: Obtiene todos los atributos con el tipado fuerte aplicado.

**Validación y Mass Assignment:**
- `validate(): array`: Valida los atributos del modelo contra las reglas definidas.
- `getFillable(): array`: Obtiene los atributos que se pueden asignar masivamente.
- `getGuarded(): array`: Obtiene los atributos protegidos.
- `isFillable(string $key): bool`: Verifica si un atributo es "fillable".
- `isGuarded(string $key): bool`: Verifica si un atributo está protegido.

**Relaciones y Consultas:**
- `query(?string $table = null): QueryBuilder`: Crea un `QueryBuilder` asociado a este modelo.
- `queryTable(?string $table = null): QueryBuilder`: Versión estática de `query()`.
- `getForeignKey(): string`: Obtiene el nombre de la clave foránea para el modelo.
- `getKeyName(): string`: Obtiene el nombre de la clave primaria.
- `getTable(): string`: Obtiene el nombre de la tabla.

**Eventos del Ciclo de Vida:**
- `on(string $event, callable $listener): void`: Registra un listener para un evento del modelo (ej. 'creating', 'saved').

---

### 4. Traits Utilizados

#### `src/Traits/HasRelationships.php`
Añade la funcionalidad de relaciones a los modelos.

- `hasOne(string $related, ?string $foreignKey = null, ?string $localKey = null): HasOne`: Define una relación uno a uno.
- `hasMany(string $related, ?string $foreignKey = null, ?string $localKey = null): HasMany`: Define una relación uno a muchos.
- `belongsTo(string $related, ?string $foreignKey = null, ?string $ownerKey = null, ?string $relation = null): BelongsTo`: Define la inversa de una relación uno a uno o uno a muchos.
- `belongsToMany(...): BelongsToMany`: Define una relación muchos a muchos.
- `getRelationValue(string $key): mixed`: Obtiene el valor de una relación cargada.
- `relationLoaded(string $key): bool`: Verifica si una relación ya ha sido cargada.

#### `src/Traits/HasStrongTyping.php`
Proporciona casting de atributos y tipado fuerte.

- `castToPhpType(string $property, mixed $value): mixed`: Convierte un valor al tipo PHP definido para una propiedad.
- `prepareValueForDatabase(string $key, mixed $value): mixed`: Prepara un valor para ser almacenado en la base de datos (ej. convierte `DateTime` a string).

#### `src/Traits/VersaORMTrait.php`
Un trait simple para inyectar una instancia de `VersaORM` en cualquier clase.

- `connectORM(array $config): void`: Conecta y almacena una instancia de `VersaORM`.
- `disconnectORM(): void`: Limpia la instancia de `VersaORM`.
- `getORM(): ?VersaORM`: Obtiene la instancia de `VersaORM` almacenada.

---

## 🎯 CONCLUSIONES

El análisis del código fuente confirma que VersaORM-PHP es un ORM maduro y rico en características. La API pública está bien definida y ofrece una amplia gama de funcionalidades que cubren desde operaciones CRUD básicas hasta construcciones de consultas complejas, manejo de relaciones y seguridad a nivel de esquema.

La estructura actual es sólida y está lista para producción. Las futuras mejoras deberían centrarse en herramientas para desarrolladores (CLI, migraciones) y optimizaciones de rendimiento, como la expansión del sistema de caché.