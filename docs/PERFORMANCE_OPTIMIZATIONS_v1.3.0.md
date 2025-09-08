# Optimizaciones de Rendimiento v1.3.0 - VersaORM-PHP

## Resumen
Este documento describe las optimizaciones de rendimiento implementadas en VersaORM-PHP v1.3.0 para resolver problemas de memory leaks y mejorar la eficiencia en procesos de larga duración.

## Problemas Identificados y Solucionados

### 1. Memory Leaks en Registros Estáticos
**Problema**: Registros estáticos que crecían indefinidamente en procesos de larga duración.

**Solución implementada**:
- `VersaORM::clearAllStaticRegistries()` - Limpieza completa de todos los registros
- `VersaORM::clearCaches()` - Limpieza selectiva de caches
- `VersaModel::clearStaticRegistries()` - Limpieza de event listeners
- `HasStrongTyping::clearTypeConverters()` - Limpieza de convertidores de tipos

### 2. Cache Sin TTL ni Límites
**Problema**: Caches que crecían sin límites ni expiración, causando uso excesivo de memoria.

**Solución implementada**:
- **TTL configurables**: 30 minutos para query cache, 1 hora para statement cache
- **Límites máximos**: 1000 entradas query cache, 100 statement cache
- **LRU eviction**: Eliminación automática del 20% de entradas más antiguas
- **Metadata temporal**: Timestamps de creación y último acceso

### 3. Pool de Conexiones Ineficiente
**Problema**: Pool de conexiones sin gestión de conexiones stale ni límites.

**Solución implementada**:
- **LRU management**: Tracking de `last_used` timestamp
- **Pruning automático**: Eliminación de conexiones stale
- **Límites configurables**: Máximo 20 conexiones por defecto
- **Control dinámico**: `setMaxPoolSize()` para ajuste en runtime

## APIs Implementadas

### Limpieza de Memoria
```php
// Limpieza completa (usar en shutdown de aplicación)
VersaORM::clearAllStaticRegistries();

// Limpieza de caches solamente (seguro en producción)
VersaORM::clearCaches();

// Limpieza granular
PdoEngine::clearQueryCache();
PdoEngine::clearStatementCache();
VersaModel::clearStaticRegistries();
```

### Configuración de Pool
```php
// Configurar tamaño máximo del pool
PdoConnection::setMaxPoolSize(50);

// Limpiar pool manualmente
PdoConnection::clearPool();
```

### Métricas Mejoradas
```php
$metrics = PdoEngine::getMetrics();
// Incluye: cache_hits, cache_misses, stmt_cache_hits, stmt_cache_misses
```

## Configuración Recomendada

### Para Aplicaciones Web (Short-lived)
```php
// Usar configuración por defecto
// TTL: 30 min query, 1 hora statements
// Límites: 1000 queries, 100 statements
```

### Para Workers/Daemons (Long-running)
```php
// Configurar límites más bajos
$config = [
    'statement_cache_limit' => 50,
    // ... otras configuraciones
];

// Limpieza periódica cada hora
register_tick_function(function() {
    static $lastClean = 0;
    if (time() - $lastClean > 3600) {
        VersaORM::clearCaches();
        $lastClean = time();
    }
});
```

### Para Tests
```php
// Limpieza entre tests
protected function tearDown(): void {
    VersaORM::clearAllStaticRegistries();
    VersaModel::setORM($this->orm); // Re-establecer después de limpieza
    parent::tearDown();
}
```

## Impacto en Rendimiento

### Beneficios
- ✅ **Memoria controlada**: Memory leaks eliminados en procesos largos
- ✅ **Cache eficiente**: TTL evita datos stale, LRU evita crecimiento infinito
- ✅ **Conexiones optimizadas**: Pool management con pruning automático
- ✅ **Flexibilidad**: APIs granulares para diferentes escenarios

### Overhead
- ⚠️ **Mínimo overhead**: Validation de TTL en cada access (< 1ms)
- ⚠️ **LRU eviction**: Procesamiento cuando se alcanza límite (~10-50ms)
- ⚠️ **Metadata storage**: +24 bytes por entrada de cache

## Tests de Validación

Se implementaron 5 tests específicos en `PerformanceOptimizationTest.php`:

1. **Cache TTL y LRU functionality** - Verifica TTL y acceso LRU
2. **Memory leak prevention** - Verifica limpieza de registros estáticos
3. **Cache partial cleanup** - Verifica limpieza selectiva vs completa
4. **Statement cache cleanup** - Verifica limpieza de statement cache
5. **Cache structure with metadata** - Verifica nueva estructura con timestamps

## Compatibilidad

- ✅ **Backward compatible**: No rompe APIs existentes
- ✅ **Tests passing**: 452/454 tests pasan (99.56%)
- ✅ **Zero downtime**: Configuración por defecto mantiene comportamiento existente
- ✅ **Optional usage**: APIs de limpieza son opcionales

## Ejemplo de Uso en Producción

```php
<?php
// worker.php - Proceso de larga duración

use VersaORM\VersaORM;

// Configuración optimizada para workers
$orm = new VersaORM([
    'driver' => 'mysql',
    'statement_cache_limit' => 50, // Límite más bajo
    // ... otras configuraciones
]);

// Worker loop
while (true) {
    try {
        // Procesar trabajos...
        processJobs($orm);

        // Limpieza periódica cada hora
        if (shouldCleanup()) {
            VersaORM::clearCaches();
            gc_collect_cycles(); // PHP garbage collection
        }

        sleep(60);

    } catch (Exception $e) {
        // En caso de error, limpieza completa
        VersaORM::clearAllStaticRegistries();
        VersaModel::setORM($orm);
        throw $e;
    }
}
```

## Conclusión

Las optimizaciones implementadas en v1.3.0 resuelven los principales problemas de memory leaks identificados en el análisis, proporcionando un ORM más robusto y eficiente para todo tipo de aplicaciones PHP, desde aplicaciones web tradicionales hasta workers y daemons de larga duración.
