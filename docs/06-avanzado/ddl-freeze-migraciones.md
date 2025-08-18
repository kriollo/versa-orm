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
Usa introspección:
```php
$cols = $orm->schema('columns','users');
// Valida presencia de last_login
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
