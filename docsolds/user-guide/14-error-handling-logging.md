# 🛡️ Manejo de Errores y Logging Avanzado en VersaORM

A partir de esta versión, VersaORM incorpora un sistema extendido de captura, enriquecimiento y persistencia de errores que facilita depuración, monitoreo y trazabilidad.

---
## 📦 Resumen de Capacidades
- Excepción unificada `VersaORMException` con metadatos enriquecidos.
- Archivos de log diferenciados (resumen y detalle) por día.
- Registro de cada excepción (incluyendo las internas del engine PDO) con traza simplificada y traza completa.
- Datos de contexto: acción ejecutada, driver, query, bindings, método origen y SQLSTATE cuando aplica.
- API para extender detalles o anotar método origen (`withOrigin()`, `withDriver()`, `augmentDetails()`).

---
## 🧱 Estructura de `VersaORMException`
Nuevos campos y helpers:

| Campo / Método | Descripción |
|----------------|-------------|
| `errorCode` | Código lógico interno (ej: `PDO_ENGINE_FAILED`, `FREEZE_VIOLATION`). |
| `query` | SQL asociado (si aplica). |
| `bindings` | Parámetros de la consulta (truncados sólo en logging externo si son extensos). |
| `sqlState` | SQLSTATE (si la excepción de PDO lo entrega). |
| `withOrigin(string $method)` | Anota el método que originó la excepción. |
| `withDriver(string $driver)` | Anota el driver activo (mysql/postgresql/sqlite). |
| `augmentDetails(array $extra)` | Agrega pares clave/valor adicionales sin sobreescribir existentes. |
| `toLogArray()` | Serializa una representación estable para logging estructurado. |
| `getRaisedAt()` | Timestamp flotante de creación. |
| `__toString()` | Resumen compacto legible (para debug rápido). |

### Ejemplo de uso manual
```php
try {
    $orm->table('users')->where('id', '=', 999)->update(['name' => null]);
} catch (VersaORMException $e) {
    // Acceso a metadatos enriquecidos
    $info = $e->toLogArray();
    var_dump($info['error_code'], $info['query'], $info['trace'][0] ?? null);
}
```

---
## 🗂️ Archivos de Log Generados
Los errores se escriben (si `log_path` está configurado o se deriva de config) en dos archivos diarios:

| Archivo | Contenido | Uso sugerido |
|---------|-----------|--------------|
| `versaorm_errors_YYYY-MM-DD.log` | 1 línea JSON por error (resumen) | Monitoreo / tail en producción |
| `versaorm_errors_detail_YYYY-MM-DD.log` | Versión extendida con `exception_log` + `full_trace` | Análisis forense / depuración profunda |

Ejemplo de entrada resumida:
```json
{
  "timestamp": "2025-08-14T15:32:10+00:00",
  "message": "PDO engine execution error: Unknown column 'xyz'",
  "error_code": "PDO_ENGINE_FAILED",
  "query": "SELECT xyz FROM users WHERE id = ?",
  "bindings": [123],
  "origin_method": "VersaORM\\VersaORM::execute",
  "driver": "mysql"
}
```

Entrada detallada (fragmento) incluye además:
```json
{
  "exception_log": {
    "raised_at": 1723649530.1234,
    "trace": [ { "i":0, "file":".../VersaORM.php", "line":995, "function":"execute" } ],
    "previous": null,
    "details": { "action":"get", "params": {"table":"users"} }
  },
  "full_trace": [ { "file":"...", "line":995, "function":"execute" }, ... ]
}
```

---
## ⚙️ Configuración Relevante
En la inicialización de `VersaORM` puedes definir:
```php
$config = [
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'app',
  'username' => 'local',
  'password' => 'local',
  'debug' => true,              // Activa modo debug (más validaciones y mensajes)
  'log_path' => __DIR__ . '/logs', // Carpeta donde se guardarán los archivos de error
];
```
Si `debug` está activo, los errores pueden incluir sugerencias adicionales (en otras partes del framework) y se fomenta su lectura directa.

---
## 🛠️ Integración con Handlers Personalizados
Puedes interceptar y centralizar reportes (ej. enviar a Sentry):
```php
use VersaORM\ErrorHandler;

ErrorHandler::setCustomHandler(function(array $errorData) {
    // $errorData contiene: error (mensaje base), code interno, trace, exception_log, contexto
    // Enviar a un agregador externo
});
```

---
## 🔒 Sanitización de Parámetros en Log
Para evitar volcado masivo de datos:
- Strings > 500 chars se truncan con `…`.
- Arrays > 50 elementos añaden indicadores `_truncated` y `_count`.
Esto se aplica en el bloque de captura interno previo al logging.

---
## 🧪 Testing / QA
Al escribir tests puedes validar campos:
```php
try {
    $orm->raw('SELECT * FROM no_table');
} catch (VersaORMException $e) {
    $this->assertSame('PDO_ENGINE_FAILED', $e->getErrorCode());
    $this->assertNotEmpty($e->toLogArray()['trace']);
}
```

---
## 🚀 Mejores Prácticas
- Define `log_path` en producción para persistir historial.
- Rota o recolecta los archivos diariamente (formato ya segmentado por fecha).
- Usa el archivo detallado sólo para análisis; monitoreo regular debe apuntar al log resumido.
- No expongas directamente el contenido de logs en respuestas HTTP.

---
## 📌 Roadmap Futuro (Opcional)
- Integración PSR-3 opcional.
- Exportador configurable (Sentry / OpenTelemetry spans).
- Filtro dinámico de campos sensibles.

---
¿Necesitas más ejemplos o integrar con un sistema de observabilidad? Abre un issue o PR.
