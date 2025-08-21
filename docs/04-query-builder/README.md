
# 🔍 Query Builder - Constructor de Consultas

El Query Builder de VersaORM es una interfaz fluida que te permite construir consultas SQL de manera programática sin escribir SQL directamente. Es especialmente útil para consultas dinámicas y complejas. **Ahora también puedes encadenar consultas sobre relaciones usando la API dual de VersaORM.**

## 🎯 ¿Cuándo usar Query Builder?

- **Consultas dinámicas**: Cuando las condiciones cambian según la lógica de negocio
- **Consultas complejas**: JOINs múltiples, subconsultas, agregaciones
- **Filtros opcionales**: Cuando algunos filtros pueden o no aplicarse
- **Paginación y ordenamiento**: Para interfaces de usuario dinámicas
- **Mejor rendimiento**: Cuando necesitas consultas optimizadas

## 📋 Contenido de esta sección

### [🔍 Consultas Simples](consultas-simples.md)
Fundamentos del Query Builder
- SELECT básico con table()
- WHERE simple con operadores
- Métodos get(), getAll(), first()
- Comparación con SQL tradicional

### [🎯 Filtros WHERE](filtros-where.md)
Domina el filtrado de datos
- Operadores de comparación (=, >, <, !=)
- Condiciones múltiples (AND, OR)
- WHERE IN, BETWEEN, LIKE
- Condiciones anidadas y complejas

### [🔗 JOINs](joins.md)
Relaciona múltiples tablas
- INNER JOIN para datos relacionados
- LEFT JOIN para datos opcionales
- RIGHT JOIN y casos especiales
- Alias de tablas y optimización

### [📊 Ordenamiento y Paginación](ordenamiento-paginacion.md)
Organiza y pagina resultados
- ORDER BY simple y múltiple
- ASC y DESC
- LIMIT y OFFSET para paginación
- Mejores prácticas de rendimiento

### [📈 Agregaciones](agregaciones.md)
Cálculos y estadísticas
- COUNT, SUM, AVG, MIN, MAX
- GROUP BY para agrupaciones
- HAVING para filtrar grupos
- Funciones de agregación complejas

## ✅ Prerrequisitos

Antes de continuar, deberías haber completado:
- ✅ [CRUD Básico](../03-basico/crud-basico.md)
- ✅ [VersaModel](../03-basico/versamodel.md)
- ✅ Comprensión básica de SQL SELECT

## 🎯 Objetivos de Aprendizaje

Al completar esta sección, sabrás:
- ✅ Construir consultas SELECT complejas sin SQL manual
- ✅ Usar todos los operadores WHERE disponibles
- ✅ Implementar JOINs entre múltiples tablas
- ✅ Paginar y ordenar resultados eficientemente
- ✅ Realizar cálculos con funciones de agregación

## ⏱️ Tiempo Estimado

- **Consultas Simples**: 15-20 minutos
- **Filtros WHERE**: 20-30 minutos
- **JOINs**: 25-35 minutos
- **Ordenamiento/Paginación**: 15-20 minutos
- **Agregaciones**: 20-30 minutos
- **Total**: 95-135 minutos


## 💡 Ejemplo Rápido

```php
// Consulta básica con Query Builder
$usuarios = $orm->table('users')
    ->where('active', '=', true)
    ->where('age', '>', 18)
    ->orderBy('name', 'ASC')
    ->limit(10)
    ->getAll();

// Encadenamiento sobre relaciones (Eloquent-style)
$user = User::findOne(1);
$totalPosts = $user->posts()->where('published', true)->count();
$primerPost = $user->posts()->orderBy('created_at', 'asc')->firstArray();

// Acceso tradicional (lazy/eager loading)
$posts = $user->posts; // Retorna los resultados directamente
```

**Devuelve:**
- QueryBuilder: array, modelo, entero, según método final (`getAll`, `count`, etc.)
- Relación: propiedad retorna resultados, método retorna objeto encadenable.

## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [Consultas Simples](consultas-simples.md)
2. **Continúa con**: [Filtros WHERE](filtros-where.md)
3. **Aprende**: [JOINs](joins.md)
4. **Domina**: [Ordenamiento y Paginación](ordenamiento-paginacion.md)
5. **Finaliza con**: [Agregaciones](agregaciones.md)
6. **Siguiente paso**: [Relaciones](../05-relaciones/README.md)

## 🚀 Próximos Pasos

Una vez que domines el Query Builder:
- **Relaciones automáticas**: [Relaciones](../05-relaciones/README.md)
- **Operaciones avanzadas**: [Funcionalidades Avanzadas](../06-avanzado/README.md)
- **Referencia completa**: [Referencia SQL](../08-referencia-sql/README.md)

## 🧭 Navegación

### ⬅️ Anterior
- [Manejo de Errores](../03-basico/manejo-errores.md)

### ➡️ Siguiente
- [Tipos de Relaciones](../05-relaciones/tipos-relaciones.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔧 Básico](../03-basico/README.md)
- [🔗 Relaciones](../05-relaciones/README.md)
- [🚀 Avanzado](../06-avanzado/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)
- [📖 Referencia SQL](../08-referencia-sql/README.md)

---

**¿Listo para consultas poderosas?** → [Comienza con Consultas Simples](consultas-simples.md) 🔍
