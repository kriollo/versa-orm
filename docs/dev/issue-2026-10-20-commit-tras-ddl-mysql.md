# Hallazgo: `COMMIT`/`ROLLBACK` tras DDL en MySQL/MariaDB lanzan «There is no active transaction»

**Encontrado el:** 2026-10-20 · **Motor:** MariaDB 11.8.8 + PHP 8.4.18 (pdo_mysql)
**Severidad:** media (bloquea migraciones DDL dentro de transacciones; arriba en `versaCLI migrate:up` de versaWYS)

## Síntoma

Dentro de `beginTransaction()` sobre MySQL/MariaDB, si se ejecuta un DDL (`CREATE`, `ALTER`, `DROP`) y luego se llama a `commit()` o `rollBack()`, VersaORM lanza:

```
VersaORMException: PDO engine execution error: There is no active transaction
```

Reproducción mínima (PdoEngine driver pdo + mysql):

```php
$orm->beginTransaction();
$orm->schemaBuilder()->create('tx_prueba', fn ($t) => $t->id()->string('nombre', 50));
$orm->commit();   // ← «There is no active transaction»
```

El mismo sintoma con `exec('CREATE ...')` + `exec('COMMIT')`, y con `rollBack()` en vez de `commit()`. El DDL en sí se aplica en disco y la conexión queda usable: sólo falla la llamada de control de transacción.

## Causa raíz

En MySQL/MariaDB **toda sentencia DDL hace autocommit implícito**: confirma la transacción activa en el servidor antes de ejecutarse. A partir de PHP 8.4 (verificado con pdo_mysql/mysqlnd), el driver PDO detecta ese commit implícito y `inTransaction()` pasa a `false` inmediatamente; además el autocommit del servidor mata la transacción en curso.

El `PdoEngine` ya tenía soporte parcial para este caso: el flag `ddlInTransaction` (marcado antes de cada DDL) ya se usaba al hacer `ROLLBACK` para limpiar la caché de esquema. Pero **faltaba el guard al llamar a `$pdo->commit()` ni `$pdo->rollBack()`**, que en PDO lanzan excepción si no hay transacción activa:

```php
// antes (src/SQL/PdoEngine.php, action 'raw'):
if (str_starts_with($normalized, 'COMMIT')) {
    $pdo->commit();                    // ← PDOException si el DDL la mató
    $this->clearAllCache();
    return null;
}
if (str_starts_with($normalized, 'ROLLBACK')) {
    $pdo->rollBack();                  // ← idem
    ...
}
```

## Impacto

Cualquier código que envuelva DDL en una transacción en MySQL/MariaDB:
- **versaWYS / MigrationManager**: `beginTransaction()` → `up()` (DDL) → insert en `versa_migrations` → `commit()`. Con cualquier migración nueva el commit explota tras haber creado las tablas (workaround previo: la migración queda registrada y las tablas creadas, pero el CLI reporta «ERROR EN MIGRACIÓN»).
- Scripts de instalador/seed que creen tablas dentro de transacciones.
- Herramientas de terceros con DDL dinámico dentro de transacciones.

## Solución (implementada en 2.2.3)

En `src/SQL/PdoEngine.php`, en el handler `raw` de transacciones, se guardó `commit()`/`rollBack()` con el estado real de PDO y se sincronizó el flag `ddlInTransaction`:

- `COMMIT`: si `inTransaction()` → commit normal + limpiar caché. Si no y `ddlInTransaction` → el DDL de MySQL ya confirmó: no-op seguro, reset del flag y limpieza de caché (el estado transaccional queda coherente).
- `ROLLBACK`: si `inTransaction()` → rollback normal. Después, si `ddlInTransaction` → reset + `clearSchemaCache()` (en PostgreSQL/SQLite el DDL sí revierte y hay que invalidar el esquema; en MySQL/MariaDB todo el DDL ya se confirmó). Limpieza de caché de resultados siempre.

El rollback sigue siendo seguro (no lanza ni deja caché inconsistente). Por otra parte, **en MySQL/MariaDB no es posible revertir un DDL con `rollBack()`** — limitación del motor (autocommit de DDL), no de la librería.

## Evidencia (repro script)

```
== Test 1: PDO puro (control) ==
inTransaction tras BEGIN: true
inTransaction tras CREATE: false      ← el driver detecta el autocommit del DDL
COMMIT FALLO: There is no active transaction

== Test 2: VersaORM raw DDL en beginTransaction ==
BEGIN ok / DROP ok / CREATE ok / INSERT ok / COMMIT OK   ← tras el fix

== Test 3: VersaORM schemaBuilder en beginTransaction ==
schemaBuilder->create ok / dropIfExists ok / COMMIT OK   ← tras el fix

== Test 4: rollback tras DDL autocommit ==
CREATE ok / ROLLBACK OK                                  ← tras el fix
```

## Pruebas de regresión

`testMysql/TransactionsRollbackTest.php`:
- `test_commit_after_ddl_in_transaction_does_not_throw`
- `test_rollback_after_ddl_in_transaction_does_not_throw`

`(4 tests, 8 assertions)` OK con MariaDB 11.8 / PHP 8.4. Suite unitaria 563 tests OK.
