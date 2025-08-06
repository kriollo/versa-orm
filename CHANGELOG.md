# Changelog

Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
