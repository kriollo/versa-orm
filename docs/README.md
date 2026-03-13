# VersaORM-PHP Documentation

Documentación completa para VersaORM-PHP con enfoque en PDO. Esta guía está diseñada para programadores con cero conocimientos en ORM, proporcionando una progresión pedagógica desde conceptos básicos hasta funcionalidades avanzadas.

## 🚀 Inicio Rápido

- **¿Nuevo en ORM?** → Comienza con [¿Qué es un ORM?](01-introduccion/que-es-orm.md)
- **¿Ya conoces ORMs?** → Ve directo a [Instalación](02-instalacion/instalacion.md)
- **¿Migras desde SQL?** → Consulta la [Referencia SQL](08-referencia-sql/)
- **¿Necesitas ejemplos?** → Cada sección incluye código ejecutable

## 📚 Estructura de la Documentación

### 📖 [01. Introducción](01-introduccion/)

_Conceptos fundamentales y comparaciones_

- [¿Qué es un ORM?](01-introduccion/que-es-orm.md) - Conceptos básicos con analogías
- [¿Por qué VersaORM?](01-introduccion/por-que-versaorm.md) - Ventajas y comparaciones

### ⚙️ [02. Instalación](02-instalacion/)

_Configuración inicial paso a paso_

- [Instalación](02-instalacion/instalacion.md) - Composer e instalación manual
- [Configuración](02-instalacion/configuracion.md) - MySQL, PostgreSQL, SQLite
- [Primer Ejemplo](02-instalacion/primer-ejemplo.md) - "Hello World" funcional

### 🔧 [03. Básico](03-basico/)

_Operaciones CRUD fundamentales_

- [CRUD Básico](03-basico/crud-basico.md) - Create, Read, Update, Delete
- [VersaModel](03-basico/versamodel.md) - dispense, load, store, trash
- [Manejo de Errores](03-basico/manejo-errores.md) - VersaORMException

### 🔍 [04. Query Builder](04-query-builder/)

_Constructor de consultas fluido_

- [Consultas Simples](04-query-builder/consultas-simples.md) - SELECT y WHERE básicos
- [Filtros WHERE](04-query-builder/filtros-where.md) - Operadores y condiciones
- [JOINs](04-query-builder/joins.md) - INNER, LEFT, RIGHT JOIN
- [Ordenamiento y Paginación](04-query-builder/ordenamiento-paginacion.md) - ORDER BY, LIMIT
- [Agregaciones](04-query-builder/agregaciones.md) - COUNT, SUM, GROUP BY

### 🔗 [05. Relaciones](05-relaciones/)

_Asociaciones entre modelos_

- [Tipos de Relaciones](05-relaciones/tipos-relaciones.md) - Conceptos y diagramas
- [hasMany y belongsTo](05-relaciones/hasMany-belongsTo.md) - Relaciones 1:N
- [Many-to-Many](05-relaciones/many-to-many.md) - Relaciones N:M con pivot
- [Eager Loading](05-relaciones/eager-loading.md) - Optimización de consultas

### 🚀 [06. Avanzado](06-avanzado/)

_Funcionalidades de productividad_

- [Eventos del Ciclo de Vida](06-avanzado/eventos-ciclo-vida.md) - hooks, listeners y triggers
- [Operaciones Batch](06-avanzado/operaciones-batch.md) - insertMany, updateMany
- [UPSERT y REPLACE](06-avanzado/upsert-replace.md) - Operaciones especiales
- [Transacciones](06-avanzado/transacciones.md) - Control de transacciones
- [Consultas Raw](06-avanzado/consultas-raw.md) - SQL directo cuando sea necesario

### 🔒 [07. Seguridad y Tipado](07-seguridad-tipado/)

_Características de seguridad_

- [Tipado Estricto](07-seguridad-tipado/tipado-estricto.md) - Sistema de tipos
- [Validación](07-seguridad-tipado/validacion.md) - Reglas automáticas y personalizadas
- [Mass Assignment](07-seguridad-tipado/mass-assignment.md) - Protección $fillable/$guarded
- [Freeze Mode](07-seguridad-tipado/freeze-mode.md) - Protección de esquema

### 📖 [08. Referencia SQL](08-referencia-sql/)

_Equivalencias SQL ↔ VersaORM_

- [SELECT](08-referencia-sql/select.md) - Consultas de selección
- [INSERT, UPDATE, DELETE](08-referencia-sql/insert-update-delete.md) - Modificación de datos
- [JOINs y Subconsultas](08-referencia-sql/joins-subqueries.md) - Consultas complejas
- [Funciones de Agregación](08-referencia-sql/funciones-agregacion.md) - Funciones SQL

## 🛠️ Configuración de Ejemplos

Todos los ejemplos en esta documentación utilizan una base de datos de ejemplo consistente. Para configurar tu entorno de pruebas:

```bash
php docs/setup/setup_database.php
```

Ver [configuración detallada](setup/README.md) para más opciones.

Para acelerar suites locales con MariaDB/PostgreSQL, revisa [Tuning de DB para tests](DatabaseTestTuning_MariaDB_PostgreSQL.md).

## 🗺️ Rutas de Aprendizaje

### 👶 **Principiante Completo**

1. [¿Qué es un ORM?](01-introduccion/que-es-orm.md)
2. [Instalación](02-instalacion/instalacion.md)
3. [CRUD Básico](03-basico/crud-basico.md)
4. [Query Builder Simple](04-query-builder/consultas-simples.md)

### 🏃 **Desarrollador con Experiencia**

1. [¿Por qué VersaORM?](01-introduccion/por-que-versaorm.md)
2. [Configuración](02-instalacion/configuracion.md)
3. [VersaModel](03-basico/versamodel.md)
4. [Relaciones](05-relaciones/)

### 🚀 **Migración desde SQL**

1. [Referencia SQL](08-referencia-sql/)
2. [Query Builder](04-query-builder/)
3. [Funcionalidades Avanzadas](06-avanzado/)
4. [Seguridad y Tipado](07-seguridad-tipado/)

## 🔍 Búsqueda Rápida

| Necesito...                 | Ve a...                                          |
| --------------------------- | ------------------------------------------------ |
| Instalar VersaORM           | [Instalación](02-instalacion/instalacion.md)     |
| Crear/leer/actualizar datos | [CRUD Básico](03-basico/crud-basico.md)          |
| Consultas complejas         | [Query Builder](04-query-builder/)               |
| Relacionar tablas           | [Relaciones](05-relaciones/)                     |
| Equivalencia SQL            | [Referencia SQL](08-referencia-sql/)             |
| Validar datos               | [Validación](07-seguridad-tipado/validacion.md)  |
| Manejar errores             | [Manejo de Errores](03-basico/manejo-errores.md) |
| Transacciones               | [Transacciones](06-avanzado/transacciones.md)    |

## 📝 Convenciones de la Documentación

- **Código ejecutable**: Todos los ejemplos se pueden copiar y ejecutar
- **SQL equivalente**: Cada ejemplo VersaORM muestra su equivalente SQL
- **Tipos de retorno**: Se especifica qué devuelve cada método
- **Progresión lógica**: Cada sección construye sobre la anterior

## 🔧 Herramientas de Desarrollo

### Formateo de Código Coordinado

Este proyecto utiliza un sistema coordinado de formateo que combina:

- **PHP-CS-Fixer** - Cumplimiento de PSR-12 y estilo base
- **Mago** - Optimizaciones adicionales de formato

#### Comandos Rápidos

```bash
# Verificar formato sin cambios
composer format-check

# Aplicar formato completo
composer format

# Scripts directos multiplataforma
.\format-code.ps1      # Windows PowerShell
./format-code.sh       # Linux/macOS Bash
```

#### Documentación Técnica

- **[Guía de Formateo](dev/formatting-guide.md)** - Coordinación completa de Mago y PHP-CS-Fixer

### Calidad de Código

- **PHPStan** - Análisis estático de tipos
- **PHPUnit** - Testing unitario y de integración
- **Composer Scripts** - Automatización de QA

## 🤝 Contribuir

Esta documentación está en constante mejora. Si encuentras errores o tienes sugerencias, por favor contribuye al proyecto.

### Para Contribuidores

1. Usa `composer format` antes de cada commit
2. Ejecuta `composer test` para validar cambios
3. Consulta la [Guía de Formateo](dev/formatting-guide.md) para mantener consistencia

---

**¿Listo para empezar?** → [Comienza con la Introducción](01-introduccion/) 🚀
