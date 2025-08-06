### Tarea 1.1: Relaciones Uno-a-Uno (HasOne, BelongsTo) [X] COMPLETADA
- [X] M�todos `hasOne` y `belongsTo` en VersaModel/traits
- [X] Lazy loading por defecto
- [X] Consultas SQL en Rust con claves for�neas/locales
- [X] Tests unitarios e integración en PHP y Rust
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de c�digo
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para an�lisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader m�s r�pido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 1.2: Relaciones Uno-a-Muchos (HasMany) [X] COMPLETADA
- [X] M�todo `hasMany` en VersaModel/traits
- [X] Consultas SQL en Rust para múltiples registros
- [X] Optimización con WHERE IN para eager loading
- [X] Tests unitarios e integración en PHP y Rust
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de c�digo
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para an�lisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader m�s r�pido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 1.3: Relaciones Muchos-a-Muchos (BelongsToMany) [X] COMPLETADA
- [X] M�todo `belongsToMany` en VersaModel/traits
- [X] Consultas SQL en Rust con JOIN y tabla pivote
- [X] Tests unitarios e integración en PHP y Rust
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de c�digo
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para an�lisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader m�s r�pido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 1.4: Lazy/Eager Loading [X] COMPLETADA
- [X] Lazy loading controlado en PHP
- [X] M�todo `with()` para eager loading
- [X] Consultas optimizadas en Rust
- [X] Generación de PHPDocs automáticos
- [X] Tests unitarios e integración en PHP y Rust
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de c�digo
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para an�lisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader m�s r�pido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 1.5: Transacciones [X] COMPLETADA
- [X] M�todos `beginTransaction`, `commit`, `rollBack` en VersaORM
- [X] Comandos de transacción en Rust
- [X] Soporte para transacciones anidadas
- [X] Tests unitarios e integración en PHP y Rust
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de c�digo
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para an�lisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader m�s r�pido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 2.2: Operaciones en Lote (Batch) ✅ COMPLETADA
- [X] Método `insertMany` en QueryBuilder
- [X] Método `updateMany` en QueryBuilder
- [X] Método `deleteMany` en QueryBuilder
- [X] Método `upsertMany` en QueryBuilder
- [X] SQL optimizado en Rust para batch
- [X] Tests unitarios e integración
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de código
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 2.3: Subconsultas y Expresiones Raw ✅ COMPLETADA
- [X] Soporte básico en QueryBuilder
- [X] Subconsultas completas en SELECT y WHERE
- [X] Métodos `selectRaw`, `orderByRaw`, `groupByRaw`
- [X] Validación segura en PHP con sistema de seguridad robusto
- [X] Tests unitarios e integración
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de código
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

** Tarea 1.6** - Validación Avanzada y Mass Assignment - **COMPLETADA**
- [X] Sanitización básica en Rust
- [X] Método `validate()` en VersaModel/traits
- [X] Validación automática desde esquema de BD (integración con metadatos Rust)
- [X] Propiedades `$fillable` y `$guarded` en modelos
- [X] Validación en `store()` y `update()`
- [X] Integración con librería de validación PHP
- [X] Validación estricta de Mass Assignment
- [X] Tests unitarios para validación y errores
- [X] Documentación actualizada
- [X] Checklist de calidad:
    - [X] Ejecutar phpstan y corregir errores PHP
    - [X] Ejecutar php-cs-fixer fix para formato de código
    - [X] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad
    - [X] Ejecutar cargo clippy y corregir errores Rust
    - [X] Compilar binario Rust y copiar a src/binary
    - [X] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [X] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 7.2: Implementación de Modo Freeze/Frozen para Modelos y Esquema [✅] COMPLETADA
- [x] Método global `$orm->freeze(true)` para activar el modo freeze en toda la aplicación
- [x] Permitir marcar modelos individuales como frozen: `User::freeze(true)`
- [x] Bloquear métodos que alteren el esquema (createTable, addColumn, dropColumn) cuando freeze está activo
- [x] Lanzar excepción si se intenta modificar el esquema o propiedades protegidas en modo freeze
- [x] Mostrar advertencia en modo desarrollo si se intenta una operación prohibida
- [x] Validar en Rust que no se ejecuten comandos DDL si freeze está activo
- [x] Propagar el estado freeze desde PHP al binario Rust en cada payload
- [x] Registrar intentos de alteración en los logs de seguridad
- [x] Tests unitarios para verificar que las operaciones prohibidas lanzan excepción en modo freeze
- [x] Documentar claramente el uso y las limitaciones del modo freeze
- [x] **🆕 FUNCIONALIDAD ADICIONAL: Creación Automática de Campos (estilo RedBeanPHP)**
  - [x] Cuando freeze está desactivado, crear automáticamente columnas faltantes
  - [x] Detección automática de tipos PHP → SQL (string→VARCHAR, int→INT, bool→BOOLEAN, etc.)
  - [x] Validación que no interfiera con el modo freeze activo
  - [x] Tests completos para verificar la creación automática de campos
  - [x] Documentación actualizada con ejemplos prácticos
- [x] Checklist de calidad:
    - [x] Ejecutar phpstan y corregir errores PHP
    - [x] Ejecutar php-cs-fixer fix para formato de código
    - [x] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad
    - [x] Ejecutar cargo clippy y corregir errores Rust
    - [x] Compilar binario Rust y copiar a src/binary
    - [x] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [x] Ejecutar tests de PHP y Rust, corregir errores y volver a validar

### Tarea 5.1: Soporte para Tipos de Datos Avanzados y Personalizados [✅] COMPLETADA
- [x] Sistema básico de manejo de tipos en `utils.rs` (`cast_types()`, `cast_value_by_type()`)
- [x] Mapeos específicos de tipos especiales (JSON, UUID, INET, ENUM, SET)
- [x] Conversiones automáticas y fallback para tipos binarios (BLOB, VARBINARY)
- [x] Soporte completo para tipos de array PostgreSQL
- [x] Archivo de configuración JSON para mappings manuales (`config/type_mappings.json`)
- [x] Tipado fuerte bidireccional Rust ↔ PHP (int, float, bool, null correctos)
- [x] Capacidades para definir manualmente tipos en VersaModel
- [x] Clases PHP con propiedades tipadas (PHP 8+) - Ejemplo: `TypedProduct.php`
- [x] Validación de esquema vs modelo
- [x] Advertencias en consola si modelo difiere del esquema
- [x] Pruebas unitarias para cada tipo especial por base de datos (`DatabaseSpecificTypesTest.php`)
- [x] Documentar tipos soportados por base de datos (`docs/user-guide/09-advanced-data-types.md`)
- [x] Checklist de calidad:
    - [x] Ejecutar phpstan y corregir errores PHP
    - [x] Ejecutar php-cs-fixer fix para formato de código
    - [x] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad
    - [x] Ejecutar cargo clippy y corregir errores Rust
    - [x] Compilar binario Rust y copiar a src/binary
    - [x] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [x] Ejecutar tests de PHP y Rust, corregir errores y volver a validar
### Tarea 5.5: Implementación de Modo Lazy y Planificador de Consultas [✅] COMPLETADA - ¡FINALIZADA!
- [x] Método ->lazy() en QueryBuilder que marque consulta como diferida
- [x] Método ->collect() para ejecutar y obtener resultado
- [x] QueryPlan intermedio en lugar de SQL inmediata
- [x] Generación de SQL final optimizada al llamar collect()
- [x] Combinar select, where, orderBy y with() en un solo SQL optimizado
- [x] Optimización de plan de ejecución:
    - [x] Analizar cadena de operaciones antes de ejecutar
    - [x] Optimizar JOINs y eliminar subconsultas innecesarias
    - [x] Combinar WHERE clauses
- [x] Validar equivalencia de resultados con consultas normales
- [x] Comparar rendimiento en operaciones encadenadas
- [x] Checklist de calidad:
    - [x] Ejecutar phpstan y corregir errores PHP
    - [x] Ejecutar php-cs-fixer fix para formato de código
    - [ ] Ejecutar psalm --plugin=psalm-security-plugin para análisis de seguridad (bloqueado por versión PHP)
    - [x] Ejecutar cargo clippy y corregir errores Rust
    - [x] Compilar binario Rust y copiar a src/binary
    - [x] Ejecutar composer dump-autoload -o genera el autoloader más rápido y liviano para entornos de despliegue
    - [x] Ejecutar tests de PHP y Rust, corregir errores y volver a validar
    - [x] Tests de equivalencia funcional (12/12 tests passing)
    - [x] Benchmarks de rendimiento lazy vs inmediato
    - [x] Documentación completa actualizada con ejemplos
