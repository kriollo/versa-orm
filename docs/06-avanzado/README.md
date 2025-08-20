# 🚀 Funcionalidades Avanzadas

Esta sección cubre las funcionalidades avanzadas de VersaORM que te permitirán manejar operaciones complejas, optimizar el rendimiento y trabajar con grandes volúmenes de datos de manera eficiente.

## 🎯 ¿Cuándo necesitas funcionalidades avanzadas?

- **Grandes volúmenes de datos**: Miles de registros a procesar
- **Operaciones complejas**: Lógica de negocio sofisticada
- **Rendimiento crítico**: Aplicaciones de alta demanda
- **Integridad de datos**: Operaciones que requieren consistencia
- **Casos especiales**: Cuando el Query Builder no es suficiente

## 📋 Contenido de esta sección

### [⚡️ Eventos del Ciclo de Vida](eventos-ciclo-vida.md)
Guía principal sobre hooks y triggers

### [🧩 Ejemplos prácticos de eventos](eventos-ciclo-vida-ejemplos.md)
Casos de uso frecuentes y comparaciones con triggers SQL
Sistema de eventos para hooks y lógica personalizada
- Registro de listeners y cancelación de operaciones
- Métodos mágicos y triggers
- Debug y testing de eventos

### [⚡ Operaciones Batch](operaciones-batch.md)
Operaciones masivas eficientes para grandes volúmenes
- `insertMany()` - Inserción masiva optimizada
- `updateMany()` - Actualización de múltiples registros
- `deleteMany()` - Eliminación masiva con condiciones
- Optimización de rendimiento y memoria

### [🔄 UPSERT y REPLACE](upsert-replace.md)
Operaciones inteligentes de inserción/actualización
- UPSERT - Insertar o actualizar según exista
- REPLACE INTO - Reemplazar registros completos
- Manejo de claves duplicadas
- Casos de uso y mejores prácticas

### [🔒 Transacciones](transacciones.md)
Control de integridad y consistencia de datos
- `beginTransaction()` - Iniciar transacción
- `commit()` - Confirmar cambios
- `rollback()` - Revertir cambios
- Transacciones anidadas y puntos de guardado

### [⚙️ Consultas Raw](consultas-raw.md)
SQL directo para casos especiales
- Cuándo usar consultas raw
- Funciones específicas de base de datos
- Procedimientos almacenados
- Optimizaciones avanzadas

### [📊 Métricas y Observabilidad](observabilidad/metricas.md)
Monitoreo ligero de rendimiento interno
- Contadores de queries / writes
- Cache hits & misses
- Latencia acumulada y última consulta
- Roadmap de extensiones

### [⚡ Batch Avanzado (inserciones optimizadas)](batch-operaciones-avanzado.md)
Profundiza en heurísticas y optimización de `insertMany`, `upsertMany` y `storeAll`
- `inserted_ids` inferidos
- Estrategias de chunking
- Errores comunes y mitigación

### [🗄️ Características Específicas por Base de Datos](caracteristicas-especificas-bases-datos.md)
Guía comparativa multi-driver (MySQL, PostgreSQL, SQLite)
- JSON / Window Functions / CTE
- Full Text / Arrays / UPSERT
- Limitaciones y adaptaciones

### [🚨 Errores y Logging](errores-logging.md)
Captura, clasificación y registro estructurado de fallos
- Categorías comunes
- Patrones de retry limitado
- Mass assignment seguro

### [🏗️ Arquitectura y Flujo Interno](arquitectura-flujo-interno.md)
Cómo se transforma una llamada de alto nivel en SQL seguro vía PDO
- Capas y responsabilidades
- Flujo de INSERT / SELECT / Batch
- Puntos de extensión actuales

### [🐢 Lazy Loading y N+1](lazy-n+1.md)
Patrones para evitar tormentas de queries y optimizar relaciones
- Pre-carga manual
- Cache en memoria ciclo
- Detección con métricas

### [🧠 Caché Interna](cache-interna.md)
Uso de la caché ligera integrada para count/exists y lecturas repetidas
- Activación y estado
- Métricas hits/misses
- Limitaciones y buenas prácticas

### [🧪 Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
Refuerza consistencia de datos y evita mass assignment
- Reglas declarativas
- Casting especializado
- Comparación de esquema

### [🧬 Datos Avanzados](datos-avanzados.md)
Tratamiento práctico de tipos especiales
- JSON / ENUM / IP / Monetario
- Arrays y blobs de texto

### [🧩 Subconsultas y RAW](subconsultas-expresiones-raw.md)
Integración segura de SQL avanzado
- Subconsultas IN / CTE
- Expresiones calculadas
- Helpers reutilizables

### [🛠️ DDL, Migraciones y Freeze](ddl-freeze-migraciones.md)
Procedimientos seguros para evolucionar el esquema
- Estrategias de cambio
- Rollback y checklist
- Uso correcto de freeze mode

### [📐 API DDL Programática](ddl-api-metodos.md)
Referencia de métodos para manipular esquema
- schemaCreate / schemaAlter
- schemaDrop / schemaRename
- Auto-creación implícita de columnas

## ✅ Prerrequisitos

Antes de continuar, deberías dominar:
- ✅ [Operaciones CRUD Básicas](../03-basico/README.md)
- ✅ [Query Builder](../04-query-builder/README.md)
- ✅ [Relaciones](../05-relaciones/README.md)
- ✅ Conceptos de transacciones en bases de datos

## 🎯 Objetivos de Aprendizaje

Al completar esta sección, sabrás:
- ✅ Procesar grandes volúmenes de datos eficientemente
- ✅ Implementar operaciones UPSERT y REPLACE
- ✅ Manejar transacciones para garantizar integridad
- ✅ Usar SQL directo cuando sea necesario
- ✅ Optimizar rendimiento en operaciones complejas

## ⏱️ Tiempo Estimado

- **Operaciones Batch**: 20-30 minutos
- **UPSERT y REPLACE**: 15-25 minutos
- **Transacciones**: 25-35 minutos
- **Consultas Raw**: 15-20 minutos
- **Total**: 75-110 minutos

## 💡 Conceptos Clave

- **Batch Operations**: Operaciones que procesan múltiples registros
- **UPSERT**: INSERT + UPDATE en una sola operación
- **ACID**: Atomicidad, Consistencia, Aislamiento, Durabilidad
- **Transaction**: Conjunto de operaciones que se ejecutan como una unidad
- **Raw Query**: Consulta SQL directa sin abstracción

## 🔧 Configuración de Ejemplos

Los ejemplos usan datos de prueba más complejos:

```bash
php docs/setup/setup_database.php
```

Incluye datos para probar operaciones masivas y transacciones.

## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [Operaciones Batch](operaciones-batch.md)
2. **Continúa con**: [UPSERT y REPLACE](upsert-replace.md)
3. **Aprende**: [Transacciones](transacciones.md)
4. **Finaliza con**: [Consultas Raw](consultas-raw.md)
5. **Siguiente paso**: [Seguridad y Tipado](../07-seguridad-tipado/README.md)

## 🚀 Próximos Pasos

Después de dominar estas funcionalidades avanzadas:
- **Seguridad robusta**: [Seguridad y Tipado](../07-seguridad-tipado/README.md)
- **Referencia completa**: [Referencia SQL](../08-referencia-sql/README.md)

## 🧭 Navegación

### ⬅️ Anterior
- [Eager Loading](../05-relaciones/eager-loading.md)

### ➡️ Siguiente
- [Tipado Estricto](../07-seguridad-tipado/tipado-estricto.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔧 Básico](../03-basico/README.md)
- [🔍 Query Builder](../04-query-builder/README.md)
- [🔗 Relaciones](../05-relaciones/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)
- [📖 Referencia SQL](../08-referencia-sql/README.md)

---

**¿Listo para el siguiente nivel?** → [Comienza con Operaciones Batch](operaciones-batch.md) ⚡
