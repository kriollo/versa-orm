# DDL, Migraciones y Freeze Mode

Buenas prácticas para cambios de esquema seguros.

## ✅ Prerrequisitos
- Operaciones CRUD y batch dominadas
- Comprender métricas básicas ([Métricas](observabilidad/metricas.md)) para evaluar impacto post-cambio
- Conocer manejo de errores ([Errores y Logging](errores-logging.md))

> Si tu app está creciendo: aquí aprendes a modificar el esquema sin sorpresas en producción.

## Conceptos
| Término | Definición |
|---------|-----------|
| DDL | Data Definition Language (ALTER, CREATE, DROP) |
| Freeze Mode | Bloqueo preventivo de operaciones DDL |
| Migración | Script que evoluciona el esquema |

## Freeze Mode
Protege producción de cambios accidentales:
```php
if ($isProduction) {
  VersaORM::freeze(true); // o configuración equivalente
}
```
Al ejecutar una sentencia DDL estando activo lanza `VersaORMException`.
**SQL que quedaría bloqueado bajo freeze:**
```sql
ALTER TABLE users ADD COLUMN last_login DATETIME NULL;
```

### Freeze por Modelo (freezeModel)
Permite congelar sólo ciertas tablas sensibles sin activar freeze global.
```php
$orm->freezeModel('users', true);   // Sólo bloquea DDL sobre users
$orm->freezeModel('logs', false);   // Permite DDL en logs
```
**SQL Equivalente bloqueado (intento):**
```sql
ALTER TABLE users ADD COLUMN secret_token VARCHAR(64);
-- Resultado: FREEZE_VIOLATION (modelo congelado)
```
Internamente se verifica el identificador normalizado antes de emitir la sentencia.

### Prioridad
| Escenario | Efecto |
|-----------|--------|
| freeze global ON, modelo sin override | Bloqueado |
| freeze global ON, freezeModel(model,false) | Permitido (override explícito) |
| freeze global OFF, freezeModel(model,true) | Bloqueado sólo ese modelo |

### Buenas Prácticas
1. Congela modelos que soportan operaciones críticas (users, payments, ledger).
2. Deja dinámicos staging / tablas temporales.
3. Registra auditoría: revisar logs de seguridad periódicamente.

### Limitaciones
- No inspecciona DDL indirecto en vistas / triggers (se recomienda revisarlos manualmente).
- Se basa en parsing sencillo de la sentencia inicial (ALTER/CREATE/DROP/RENAME). Evita concatenar múltiples sentencias separadas por `;`.

---
## Notas Dialectales de Migraciones Rápidas
| Operación | MySQL | PostgreSQL | SQLite |
|-----------|-------|------------|--------|
| Renombrar columna | `ALTER TABLE t RENAME COLUMN a TO b` (>=8) | Igual | Copia tabla (emulado internamente en versiones viejas) |
| Modificar tipo + NOT NULL | `MODIFY COLUMN` | `ALTER COLUMN ... TYPE` + `ALTER COLUMN ... SET NOT NULL` | Emulación recreando tabla |
| Agregar columna con DEFAULT | Inmediato | Inmediato (expresión constante) | Puede requerir recrear tabla si versión antigua |
| Índice concurrente | `ALGORITHM=INPLACE`/online parcial | `CREATE INDEX CONCURRENTLY` | No concurrente |
| DROP CONSTRAINT FK | `DROP FOREIGN KEY` | `DROP CONSTRAINT` | No FK named (usa pragma, emulado) |

**SQL Ejemplo multi-dialecto (cambiar tamaño email y hacerlo NOT NULL):**
```sql
-- MySQL
ALTER TABLE users MODIFY COLUMN email VARCHAR(320) NOT NULL;
-- PostgreSQL
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(320);
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
-- SQLite (emulación típica): crear tabla nueva, copiar datos, renombrar.
```

---

## Flujo Recomendado de Migraciones
1. Revisión local + test.
2. Aplicar en staging.
3. Backup / snapshot.
4. Ejecutar migración en producción (ventana controlada).
5. Activar freeze nuevamente (si se desactiva temporalmente).

## Script SQL Ejemplo
```sql
ALTER TABLE users ADD COLUMN last_login DATETIME NULL;
CREATE INDEX idx_users_last_login ON users(last_login);
```
**Rollback (inverso):**
```sql
DROP INDEX idx_users_last_login;
ALTER TABLE users DROP COLUMN last_login;
```

## Orden Seguro de Cambios
| Tipo | Estrategia |
|------|-----------|
| Añadir columna nullable | Directo |
| Añadir columna NOT NULL | Añadir como nullable → poblar → alterar a NOT NULL |
| Renombrar columna | Crear nueva + copiar datos + actualizar código + eliminar vieja |
| Eliminar columna | Asegurar no usada → backup → eliminar |

## Rollback Básico
Mantén script inverso:
```sql
DROP INDEX idx_users_last_login;
ALTER TABLE users DROP COLUMN last_login;
```

## Comprobación de Esquema
Usa el SchemaBuilder moderno para introspección:
```php
use VersaORM\Schema\VersaSchema;

// Verificar existencia de tabla
if (VersaSchema::hasTable('users')) {
    echo "Tabla users existe\n";
}

// Verificar existencia de columna
if (VersaSchema::hasColumn('users', 'last_login')) {
    echo "Columna last_login existe\n";
}

// Obtener información detallada de columnas
$schema = $orm->schemaBuilder();
$cols = $schema->getColumns('users');
foreach ($cols as $col) {
    echo "{$col['name']} ({$col['type']})\n";
}
```
**SQL subyacente (driver MySQL):**
```sql
SHOW COLUMNS FROM users;
```

## Checklist Pre-Deploy
- [ ] Backups verificados
- [ ] Scripts probados en staging
- [ ] Plan de rollback escrito
- [ ] Ventana de mantenimiento acordada
- [ ] Freeze reactivado al final

## Evitar
- Cambios masivos sin índice previo en columnas de filtro.
- Alterar tipo de columna grande sin plan de lock.
- Eliminar columna aún referenciada por código activo.

## Monitoreo Post Migración
- Revisar métricas de queries anómalas.
- Verificar ausencia de errores de integridad.
- Ejecutar tests de humo (login, CRUD básico).

## ➡️ Próximos Pasos
- Revisar arquitectura general: [Arquitectura y Flujo Interno](arquitectura-flujo-interno.md)
- Optimizar acceso a datos: [Lazy y N+1](lazy-n+1.md)
- Validar consistencia de tipos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
