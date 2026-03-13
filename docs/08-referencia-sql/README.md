# 📖 Referencia SQL - VersaORM

Esta sección proporciona una referencia completa de equivalencias entre instrucciones SQL tradicionales y métodos VersaORM. Es especialmente útil para desarrolladores que ya conocen SQL y quieren migrar a VersaORM o necesitan una referencia rápida.

## 🎯 ¿Para quién es esta referencia?

- **Desarrolladores SQL experimentados**: Migración rápida a VersaORM
- **Equipos mixtos**: Algunos usan SQL, otros VersaORM
- **Consulta rápida**: Encontrar equivalencias específicas
- **Aprendizaje comparativo**: Entender VersaORM desde SQL
- **Debugging**: Verificar qué SQL genera VersaORM

## 📋 Contenido de esta sección

### [🔍 SELECT - Consultas de Selección](select.md)
Todas las variantes de SELECT y equivalencias
- SELECT básico y con condiciones WHERE
- DISTINCT, ORDER BY, LIMIT, OFFSET
- Subconsultas y consultas complejas
- Funciones de ventana y casos especiales
- Alias de columnas y tablas

### [✏️ INSERT, UPDATE, DELETE - Operaciones de Modificación](insert-update-delete.md)
Operaciones de modificación de datos
- INSERT simple y múltiple
- UPDATE con condiciones complejas
- DELETE con filtros y JOINs
- Operaciones UPSERT y REPLACE
- Manejo de claves duplicadas

### [🔗 JOINs y Subconsultas](joins-subqueries.md)
Consultas complejas con múltiples tablas
- INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL OUTER JOIN
- Subconsultas en SELECT, WHERE, FROM, HAVING
- Consultas correlacionadas y no correlacionadas
- CTEs (Common Table Expressions) cuando sea posible
- Optimización de JOINs complejos

### [📊 Funciones de Agregación](funciones-agregacion.md)
Funciones SQL y sus equivalentes VersaORM
- COUNT, SUM, AVG, MIN, MAX
- GROUP BY y HAVING con múltiples condiciones
- Funciones de fecha y string
- Funciones matemáticas y estadísticas
- Funciones de ventana (window functions)

## 📚 Cómo usar esta referencia

Cada página incluye:
- **SQL Original**: La consulta SQL tradicional
- **VersaORM Equivalente**: El código VersaORM correspondiente
- **Tipo de Retorno**: Qué devuelve cada método exactamente
- **Notas**: Diferencias importantes, limitaciones o ventajas
- **Casos de Uso**: Cuándo usar cada aproximación

## 💡 Ejemplo de formato

```sql
-- SQL
SELECT name, email FROM users WHERE active = 1 ORDER BY name LIMIT 10;
```

```php
// VersaORM
$users = $orm->table('users')
    ->select(['name', 'email'])
    ->where('active', '=', 1)
    ->orderBy('name')
    ->limit(10)
    ->getAll();
```

**Devuelve:** Array de arrays asociativos con las columnas seleccionadas.

**Nota:** VersaORM optimiza automáticamente la consulta y maneja la conversión de tipos.

## ✅ Prerrequisitos

Para aprovechar al máximo esta referencia:
- ✅ Conocimientos sólidos de SQL
- ✅ Comprensión básica de VersaORM
- ✅ Experiencia con [Query Builder](../04-query-builder/README.md)

## 🎯 Objetivos de esta referencia

Al usar esta sección, podrás:
- ✅ Traducir cualquier consulta SQL a VersaORM
- ✅ Entender qué SQL genera cada método VersaORM
- ✅ Optimizar consultas comparando ambas aproximaciones
- ✅ Migrar proyectos existentes de SQL a VersaORM
- ✅ Resolver dudas específicas de sintaxis

## ⏱️ Uso Recomendado

- **Consulta rápida**: 2-5 minutos por equivalencia
- **Migración de proyecto**: Varias horas según complejidad
- **Aprendizaje sistemático**: 60-90 minutos para toda la sección

## 🔧 Configuración de Ejemplos

Los ejemplos usan el esquema estándar de la documentación:

```bash
php docs/setup/setup_database.php
```

Incluye tablas: `users`, `posts`, `tags`, `post_tags`, `orders`, `products`

## 🗺️ Progresión Recomendada

1. **Empieza aquí**: [SELECT](select.md) - Lo más común
2. **Continúa con**: [INSERT, UPDATE, DELETE](insert-update-delete.md)
3. **Aprende**: [JOINs y Subconsultas](joins-subqueries.md)
4. **Domina**: [Funciones de Agregación](funciones-agregacion.md)

## 🔍 Búsqueda Rápida por Función SQL

| Función SQL | Ve a... |
|-------------|---------|
| SELECT, WHERE, ORDER BY | [SELECT](select.md) |
| INSERT, UPDATE, DELETE | [INSERT, UPDATE, DELETE](insert-update-delete.md) |
| JOIN, INNER JOIN, LEFT JOIN | [JOINs y Subconsultas](joins-subqueries.md) |
| COUNT, SUM, AVG, GROUP BY | [Funciones de Agregación](funciones-agregacion.md) |
| Subconsultas, EXISTS, IN | [JOINs y Subconsultas](joins-subqueries.md) |
| DISTINCT, LIMIT, OFFSET | [SELECT](select.md) |
| HAVING, MIN, MAX | [Funciones de Agregación](funciones-agregacion.md) |

## 🧭 Navegación

### ⬅️ Anterior
- [Freeze Mode](../07-seguridad-tipado/freeze-mode.md)

### 🏠 Otras Secciones
- [🏠 Inicio](../README.md)
- [📖 Introducción](../01-introduccion/README.md)
- [⚙️ Instalación](../02-instalacion/README.md)
- [🔧 Básico](../03-basico/README.md)
- [🔍 Query Builder](../04-query-builder/README.md)
- [🔗 Relaciones](../05-relaciones/README.md)
- [🚀 Avanzado](../06-avanzado/README.md)
- [🔒 Seguridad](../07-seguridad-tipado/README.md)

---

**¿Listo para las equivalencias?** → [Comienza con SELECT](select.md) 🔍
