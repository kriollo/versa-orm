# 🔗 Relaciones entre Modelos

Las relaciones son una de las características más poderosas de VersaORM, permitiendo modelar y trabajar con asociaciones entre tablas de manera intuitiva y eficiente. Simplifican enormemente el trabajo con datos relacionados.

## 🎯 ¿Por qué son importantes las relaciones?

- **Modelado natural**: Reflejan las relaciones del mundo real
- **Código más limpio**: Menos consultas SQL manuales
- **Optimización automática**: VersaORM optimiza las consultas
- **Mantenimiento fácil**: Cambios centralizados en los modelos

## 📋 Contenido de esta sección

### [📊 Tipos de Relaciones](tipos-relaciones.md)
Conceptos fundamentales y diagramas explicativos
- Relaciones 1:1 (Uno a Uno)
- Relaciones 1:N (Uno a Muchos)
- Relaciones N:M (Muchos a Muchos)
- Claves foráneas y convenciones

### [👥 Relaciones Uno-a-Muchos (hasMany/belongsTo)](hasMany-belongsTo.md)
Implementación de relaciones padre-hijo
- hasMany: Un usuario tiene muchos posts
- belongsTo: Un post pertenece a un usuario
- Definición en modelos
- Uso práctico con ejemplos

### [🔄 Relaciones Muchos-a-Muchos](many-to-many.md)
Manejo de relaciones complejas con tablas pivot
- belongsToMany: Posts ↔ Tags
- Tablas pivot y convenciones
- Datos adicionales en pivot
- Sincronización de relaciones

### [⚡ Carga Eager vs Lazy](eager-loading.md)
Optimización de consultas y rendimiento
- Lazy Loading: Carga bajo demanda
- Eager Loading: Carga anticipada
- Problema N+1 y soluciones
- Estrategias de optimización

## ✅ Prerrequisitos

Antes de continuar, deberías dominar:
- ✅ [CRUD Básico](../03-basico/crud-basico.md)
- ✅ [Query Builder](../04-query-builder/README.md)
- ✅ Conceptos básicos de bases de datos relacionales
- ✅ Claves primarias y foráneas

## 🎯 Objetivos de Aprendizaje

Al completar esta sección, sabrás:
- ✅ Definir relaciones entre modelos VersaORM
- ✅ Implementar relaciones 1:N y N:M
- ✅ Optimizar consultas con eager loading
- ✅ Trabajar con tablas pivot
- ✅ Evitar problemas comunes de rendimiento

## ⏱️ Tiempo Estimado

- **Tipos de Relaciones**: 15-20 minutos
- **hasMany/belongsTo**: 25-35 minutos
- **Many-to-Many**: 30-40 minutos
- **Eager Loading**: 20-30 minutos
- **Total**: 90-125 minutos

## 💡 Conceptos Clave

- **Relación**: Asociación lógica entre dos o más tablas
- **Clave Foránea**: Campo que referencia la clave primaria de otra tabla
- **Tabla Pivot**: Tabla intermedia para relaciones muchos-a-muchos
- **Lazy Loading**: Carga de relaciones bajo demanda
- **Eager Loading**: Carga anticipada de relaciones
- **N+1 Problem**: Problema de rendimiento con múltiples consultas

## 🔧 Configuración de Ejemplos

Los ejemplos usan un esquema de blog con usuarios, posts y tags:

```bash
php docs/setup/setup_database.php
```

Tablas incluidas: `users`, `posts`, `tags`, `post_tags`

## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [Tipos de Relaciones](tipos-relaciones.md)
2. **Continúa con**: [hasMany/belongsTo](hasMany-belongsTo.md)
3. **Aprende**: [Many-to-Many](many-to-many.md)
4. **Optimiza con**: [Eager Loading](eager-loading.md)
5. **Siguiente paso**: [Funcionalidades Avanzadas](../06-avanzado/README.md)

## 🚀 Próximos Pasos

Una vez que domines las relaciones:
- **Operaciones avanzadas**: [Funcionalidades Avanzadas](../06-avanzado/README.md)
- **Seguridad**: [Seguridad y Tipado](../07-seguridad-tipado/README.md)
- **Referencia completa**: [Referencia SQL](../08-referencia-sql/README.md)

## 🧭 Navegación

### ⬅️ Anterior
- [Agregaciones](../04-query-builder/agregaciones.md)

### ➡️ Siguiente
- [Operaciones Batch](../06-avanzado/operaciones-batch.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔧 Básico](../03-basico/README.md)
- [🔍 Query Builder](../04-query-builder/README.md)
- [🚀 Avanzado](../06-avanzado/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)
- [📖 Referencia SQL](../08-referencia-sql/README.md)

---

**¿Listo para conectar tus datos?** → [Comienza con Tipos de Relaciones](tipos-relaciones.md) 🔗
