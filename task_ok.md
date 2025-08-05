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
