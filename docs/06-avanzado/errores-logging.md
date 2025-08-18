# Manejo de Errores y Logging

Guía práctica para capturar, interpretar y registrar errores en VersaORM-PHP (modo PDO).

## ✅ Prerrequisitos
- Haber realizado operaciones básicas ([CRUD Básico](../03-basico/crud-basico.md))
- Conocer `store()` y `storeAll()`
- Nociones de batch ([Operaciones Batch Avanzadas](batch-operaciones-avanzado.md))

> Si vienes de CRUD: aquí aprendes a endurecer tu código frente a fallos y a registrar información útil sin exponer detalles sensibles.

## Excepción Base
Todas las condiciones de error del ORM lanzan `VersaORM\\VersaORMException`.

```php
use VersaORM\VersaORMException;

try {
    $user = VersaModel::dispense('users');
    $user->email = 'invalido';
    $user->store();
} catch (VersaORMException $e) {
    // Mensaje humano
    echo $e->getMessage();
    // Código interno (cuando se defina)
    // echo $e->getCode();
}
```

## Categorías Comunes
| Categoría | Contexto típico | Ejemplo de mensaje |
|-----------|-----------------|--------------------|
| SQL | Error sintáctico / constraint | "SQLSTATE[23000]: Integrity constraint violation..." |
| Validación / Casting | Tipo incompatible o conversión fallida | "Tipo boolean inválido para campo active" |
| Freeze Mode | Intento de DDL en modo congelado | "Operation blocked by freeze mode" |
| Batch | Datos inconsistentes en lotes | "updateMany: missing primary key in row" |
| Relación | Acceso a relación inexistente | "Undefined relation commentsArray" |

## Estructura Recomendada del Bloque try/catch
```php
try {
    $ids = VersaModel::storeAll($modelos);
    // ... lógica adicional
} catch (VersaORMException $e) {
    error_log('[ORM] ' . $e->getMessage());
    // Re-lanzar o mapear a excepción de dominio
    throw $e; // o DomainException::fromOrm($e);
}
```

## Logging Básico
Sin configurar nada extra, puedes usar `error_log()` o un logger PSR-3 externo:
```php
$logger->error('Falló operación batch', ['exception' => $e]);
```

## Patrón de Envoltorio (Wrapper)
Centraliza interceptación de errores:
```php
function withOrm(callable $fn) {
    try { return $fn(); }
    catch (VersaORMException $e) {
        error_log('[ORM] ' . $e->getMessage());
        throw $e; // o transformar
    }
}
$ids = withOrm(fn() => VersaModel::storeAll($lote));
```

## Freeze Mode (Resumen)
Si activas modo freeze y ejecutas una operación DDL:
```php
try {
    $orm->raw('ALTER TABLE users ADD COLUMN tmp INT');
} catch (VersaORMException $e) {
    error_log('Bloqueado: ' . $e->getMessage());
}
```
Mantén este modo en producción para proteger contra cambios accidentales de esquema.

## Validación y Mass Assignment
Implementa whitelists antes de asignar datos externos:
```php
$permitidos = ['name','email','active'];
foreach ($input as $k=>$v) {
    if (!in_array($k,$permitidos, true)) {
        error_log("MASS_ASSIGNMENT bloqueado: $k");
        continue;
    }
    $user->$k = $v;
}
```

## Batch: Errores Comunes
| Problema | Causa | Estrategia |
|----------|-------|-----------|
| IDs perdidos en updateMany | Fila sin PK | Validar antes de llamar |
| Violación UNIQUE en upsertMany | Dato duplicado concurrente | Retentar con backoff si corresponde |
| Desfase de inserted_ids | Inferencia no aplicable | Recuperar individualmente si crítico |

## Reintentos Seguros
Solo para errores transitorios (deadlocks, timeouts). Evita reintentar violaciones de integridad.
```php
function retry(int $n, callable $op) {
  inicio:
  try { return $op(); }
  catch (VersaORMException $e) {
    if ($n-- <= 0) throw $e;
    usleep(100_000); // 100ms
    goto inicio;
  }
}
```

## Estructura de Logs Sugerida
Formato simple por línea:
```
[fecha hora] nivel contexto mensaje | extra
```
Ejemplo:
```
[2025-08-17 10:12:01] ERROR ORM batch insert failed | tabla=users filas=120
```

## Buenas Prácticas
- Normaliza mensajes: prefijo `[ORM]`.
- Registra tamaño de lote y tiempo para diagnósticos.
- No expongas mensajes SQL crudos al usuario final.
- Mapear a excepciones de dominio en la capa de aplicación.

## Checklist Rápido
- [ ] Capturas `VersaORMException`
- [ ] Separas errores transitorios de lógicos
- [ ] Evitas reintentos infinitos
- [ ] Logueas lotes grandes
- [ ] Proteges contra mass assignment

## ➡️ Próximos Pasos
- Optimizar rendimiento: [Métricas](observabilidad/metricas.md)
- Profundizar en cambios de esquema: [DDL / Freeze](ddl-freeze-migraciones.md)
- Asegurar consistencia de tipos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
