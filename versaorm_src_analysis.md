VersaORM - Análisis de cuellos de botella y fugas de memoria (carpeta `src`)

Fecha: 25 de agosto de 2025

Resumen ejecutivo
-----------------
He realizado un análisis estático profundo del código dentro de la carpeta `src` para identificar posibles cuellos de botella de rendimiento, fugas de memoria y riesgos operacionales, con foco en patrones que impactan aplicaciones PHP de larga vida (workers, FPM persistente) y en la integración con el binario Rust.

Áreas analizadas
-----------------
- `VersaORM.php` (comunicación con binario Rust, manejo de payloads temporales, limpieza de salida)
- `VersaModel.php` (ActiveRecord, manejo de atributos, eventos estáticos)
- `QueryBuilder.php` (generación de operaciones y subqueries, lazy operations)
- `SQL/PdoEngine.php` (caché de resultados, cache de sentencias preparadas, métricas, hidratación)
- `SQL/PdoConnection.php` (pool de conexiones, manejo de PDO)
- `ErrorHandler.php` (registro, tamaño de logs, formatters)
- `ModelEvent.php`, `VersaORMException.php`, traits (`HasStrongTyping`, `HasRelationships`)

Hallazgos clave
--------------
1) Llamadas al binario Rust (I/O y procesos)
- `VersaORM::executeBinaryWithTempFile` usa `proc_open` para mocks de PowerShell y `shell_exec` con archivos temporales para binarios reales.
- Riesgos:
  - shell_exec bloqueante puede incurrir en tiempo de espera y bloqueo de procesos en entornos de alta concurrencia.
  - Uso de archivos temporales y eliminación asegura limpieza, pero hay posibilidad de race/permissions en entornos Windows y contenedores con /tmp compartido.
  - No hay límite de tiempo (timeout) al ejecutar el binario; si el proceso cuelga, la petición PHP puede bloquear indefinidamente.
  - proc_open maneja correctamente pipes pero en el camino de error existe riesgo de no cerrar recursos si no se captura todo. Sin embargo, el código cierra los pipes en catch.

Recomendaciones:
- Reemplazar `shell_exec` por `proc_open` o `Symfony Process` en todos los casos para poder imponer timeouts y control fino de IO.
- Implementar un timeout configur able (por ejemplo `vor_binary_timeout_ms`) y matar proceso si excede.
- Validar y limitar el tamaño del payload antes de escribirlo en fichero o pasarlo por stdin.
- Añadir retries/backoff y circuit breaker cuando el binario devuelva errores persistentes.

2) Pool de conexiones y gestión de PDO
- `PdoConnection` mantiene un pool estático `private static array $pool` indexado por DSN+credenciales.
- Riesgos:
  - Para CLI/long-running workers, el pool puede mantener referencias a PDO que consumen recursos si no se limpian (aunque `PdoConnection::close()` establece `$this->pdo = null`, el pool sigue manteniendo la referencia si fue poblado).
  - En procesos PHP que manejan múltiples configuraciones/usuarios, la clave del pool (`mysql|...|user|pass`) puede crecer de forma ilimitada.

Recomendaciones:
- Añadir un límite configurable al tamaño del pool y una política LRU para evictar entradas antiguas.
- Proveer una API pública para limpiar el pool (por ejemplo `PdoConnection::clearPool()`), y llamar a esta en `VersaORM::disconnect()` cuando sea apropiado.
- Para SQLite :memory:, mantener comportamiento actual pero documentar limitación para procesos con muchos DB distintos.

3) Caché de sentencias preparadas (stmt cache)
- Implementado en `PdoEngine` como `private static array $stmtCache` con LRU simple.
- Riesgos:
  - Se almacena un objeto `PDOStatement` como valor estático. Algunos drivers no permiten reutilizar statements tras cerrar cursors o reconexión; puede causar errores si la conexión fue renovada.
  - El límite `stmtCacheLimit` existe, pero no hay control fino de memoria por entrada; si se cachean many statements con SQL muy grandes, puede crecer.
  - array_shift para evicción puede ser O(n) en arrays grandes repetidamente.

Recomendaciones:
- En lugar de almacenar directamente `PDOStatement`, almacenar un descriptor (clave) y re-preparear si el statement no es válido.
- Alternativamente, cachear SQL + metadata pero no el objeto statement entre requests en entornos FPM where persistent connections are handled by container.
- Reemplazar evicción con SplDoublyLinkedList+Hash o usar una estructura LRU específica (extensión/PSR cache) para eficiencia.
- Añadir validación que verifique que la `PDO` asociada sigue viva antes de reutilizar el statement.

4) Caché de resultados (query cache)
- `PdoEngine` tiene `private static array $queryCache` y `private static array $tableKeyIndex` cuando `cache` está activado.
- Riesgos:
  - Caché en memoria no limitada puede crecer indefinidamente en procesos de larga vida.
  - No hay políticas de expiración TTL ni límites por tamaño.

Recomendaciones:
- Implementar límites y TTLs configurables; considerar usar APCu o un backend externo (Redis) para cargas grandes.
- Añadir métricas de memoria usadas por la caché y un mecanismo de purgado cuando supere umbral.
- Para invalidación por tabla, asegurar sincronización segura y evitar race conditions en ambientes multi-proceso.

5) Métricas y monitoreo
- `PdoEngine::getMetrics()` provee métricas útiles. Sin embargo, las métricas acumuladas son estáticas y podrían enmascarar actividad entre tenants en procesos multi-tenant.

Recomendaciones:
- Hacer que las métricas puedan ser instanciadas en modo no estático si se desea seguimiento por instancia.
- Añadir hooks para exportar métricas a Prometheus/StatsD.

6) Registries y handlers estáticos (HasStrongTyping, EventListeners)
- Traits mantienen registries estáticos (conversores, listeners) para velocidad.
- Riesgos:
  - Registros estáticos pueden provocar fugas si se añaden programáticamente por cada petición (scripts, test runners) sin limpiarse.
  - Event listeners estáticos pueden retener closures con referencias externas (capturas) y provocar fugas de memoria.

Recomendaciones:
- Documentar que registries son globales y exponer API para limpiar (ya existe `VersaModel::clearEventListeners()`). Añadir `clearTypeConverters()` en el trait `HasStrongTyping`.
- Evitar capturar `$this` en closures para listeners; usar callables estáticos o metadata.
- En entornos de pruebas, llamar a las funciones de limpieza en tearDown().

7) Hidratación de objetos y creación masiva
- `PdoEngine` registra métricas de hidratación y tiene un "fast-path" en algunas operaciones. Crear objetos `VersaModel` repetidamente para grandes result sets es costoso.

Recomendaciones:
- Si el usuario requiere arrays, ofrecer una opción más explícita para evitar hidratación (ya existe `get()` vs `findAll()`); documentar y optimizar `get()`.
- Implementar una pool de objetos ligeros o reutilizable para evitar GC intenso en cargas masivas (opcional, complejo).
- Evaluar lazy-hydration: crear modelos solo cuando se accede a propiedades.

8) Uso de JSON y parsing
- `VersaORM::cleanRustDebugOutput` intenta extraer JSON desde salida con debug logs; usa `json_decode` sin JSON_THROW_ON_ERROR en algunas ramas.

Recomendaciones:
- Usar `json_decode(..., true, 512, JSON_THROW_ON_ERROR)` donde sea apropiado y capturar `JsonException` para diagnósticos.
- Limitar tamaño permitido para la salida JSON para defender contra OOM por payloads inesperadamente grandes.

9) Manejo de archivos temporales
- Se crean archivos temporales con `tempnam` y `file_put_contents(..., LOCK_EX)` para pasar datos al binario. Se eliminan en finally.

Riesgos:
- Race conditions si múltiples procesos usan el mismo nombre (aunque tempnam evita); problemas de permisos en entornos restringidos.

Recomendaciones:
- Considerar usar pipes (`proc_open`) siempre que sea posible para evitar fs I/O.
- Si se sigue usando archivos, usar rutas configurables y limpiar registros en logs.

Acciones propuestas de refactor (priorizadas)
--------------------------------------------
1) Reemplazar `shell_exec` por `proc_open` con timeout y control de IO. (Alto impacto, baja complejidad)
2) Añadir timeout configurable y circuit breaker para llamadas al binario. (Alto impacto)
3) Implementar límite y LRU para `PdoConnection::$pool` y exponer `clearPool()` y `prunePool()` API. (Medio)
4) Cambiar `PdoEngine::$stmtCache` para no almacenar `PDOStatement` directamente o validar la conexión antes de reusar. (Medio-Alto)
5) Añadir TTL y límite de tamaño al `queryCache` o permitir backend opcional (APCu/Redis). (Medio)
6) Documentar y añadir API para limpiar registries estáticos (type converters, event listeners). (Bajo)
7) Añadir validaciones/limits en `cleanRustDebugOutput` y parseo seguro de JSON. (Bajo)

Pruebas y validación recomendadas
---------------------------------
- Crear tests de integración que simulen fin del binario (timeout, salida corrupta).
- Tests para pool LRU y stmtCache evictions.
- Tests de memoria que ejecuten cargas masivas (insertMany, get con 100k filas) y comparen peak memory.

Cobertura de requisitos
-----------------------
- Analizar sólo `src`: Done
- Identificar cuellos de botella y fugas de memoria: Done
- Guardar análisis en la raíz: Done (archivo `versaorm_src_analysis.md`)
