# ⚡ Modo Lazy y Planificador de Consultas

¡Bienvenido al Modo Lazy de VersaORM! Esta funcionalidad revolucionaria optimiza automáticamente tus consultas para obtener el máximo rendimiento con el mínimo esfuerzo.

## 🤔 ¿Qué es el Modo Lazy?

El **Modo Lazy** es un sistema inteligente que retrasa la ejecución de consultas hasta que realmente necesitas los datos, permitiendo que VersaORM optimice toda la cadena de operaciones antes de ejecutarla.

### 🔄 La Diferencia es Revolucionaria

**❌ ANTES (Ejecución Inmediata - Ineficiente):**
```php
// Cada operación genera una consulta SQL inmediata
$query = $orm->table('users')
    ->where('status', '=', 'active');     // SQL: SELECT * FROM users WHERE status = 'active'

$query = $query->where('age', '>=', 18); // SQL: SELECT * FROM users WHERE status = 'active' AND age >= 18

$query = $query->orderBy('created_at', 'desc'); // SQL: SELECT * FROM users WHERE... ORDER BY created_at DESC

$users = $query->getAll(); // ¡Finalmente ejecuta la consulta!

// Problemas:
// ❌ Múltiples construcciones de SQL innecesarias
// ❌ No hay optimización de la consulta final
// ❌ Desperdicio de recursos del procesador
// ❌ Consultas subóptimas
```

**✅ DESPUÉS (Modo Lazy - Optimizado Automáticamente):**
```php
// Las operaciones se acumulan sin ejecutarse
$users = $orm->table('users')
    ->lazy()                              // 🚀 Activa el modo lazy
    ->where('status', '=', 'active')      // ⏸️ Se acumula (no ejecuta)
    ->where('age', '>=', 18)              // ⏸️ Se acumula (no ejecuta)
    ->orderBy('created_at', 'desc')       // ⏸️ Se acumula (no ejecuta)
    ->collect();                          // ✅ Optimiza y ejecuta UNA sola consulta perfecta

// Ventajas:
// ✅ Una sola consulta SQL optimizada
// ✅ El planificador optimiza automáticamente
// ✅ Mejor rendimiento y menos carga en la DB
// ✅ Combina WHERE clauses inteligentemente
// ✅ Optimiza JOINs automáticamente
```

## 🚀 Comenzando con el Modo Lazy

**Para activar el modo lazy**, simplemente añade `->lazy()` después de especificar la tabla:

```php
$query = $orm->table('users')->lazy(); // ¡Modo lazy activado!
```

---

## 🎯 Métodos del Modo Lazy

### `lazy()` - Activar Modo Lazy

Convierte cualquier query builder en modo lazy, acumulando operaciones para optimización posterior.

```php
$query = $orm->table('users')->lazy();
```

### `collect()` - Ejecutar y Obtener Resultados

Ejecuta la consulta optimizada y devuelve los resultados.

```php
$users = $orm->table('users')
    ->lazy()
    ->where('active', '=', true)
    ->collect(); // Ejecuta y devuelve los datos
```

### `explain()` - Ver el Plan de Ejecución

Obtiene información detallada sobre cómo VersaORM optimizará y ejecutará tu consulta.

```php
$plan = $orm->table('users')
    ->lazy()
    ->where('status', '=', 'active')
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->explain();

echo "Plan de ejecución: " . json_encode($plan, JSON_PRETTY_PRINT);
```

---

## 🔧 Ejemplos Prácticos

### Ejemplo 1: Consulta Simple Optimizada

**❌ Forma Tradicional:**
```php
// Múltiples construcciones SQL
$baseQuery = $orm->table('users');
$withStatus = $baseQuery->where('status', '=', 'active');
$withAge = $withStatus->where('age', '>=', 21);
$ordered = $withAge->orderBy('name');
$users = $ordered->getAll();

// Resultado: Múltiples operaciones de construcción SQL
```

**✅ Con Modo Lazy:**
```php
// Una sola consulta optimizada
$users = $orm->table('users')
    ->lazy()
    ->where('status', '=', 'active')
    ->where('age', '>=', 21)
    ->orderBy('name')
    ->collect();

// Resultado: UNA consulta SQL perfectamente optimizada
// SQL final: SELECT * FROM users WHERE status = 'active' AND age >= 21 ORDER BY name
```

### Ejemplo 2: Consultas con Relaciones Optimizadas

**❌ Forma Tradicional:**
```php
// Consultas separadas o JOINs manuales
$users = $orm->table('users')
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->where('users.active', '=', true)
    ->where('posts.published', '=', true)
    ->getAll();

// Problemas:
// ❌ JOINs no optimizados
// ❌ Posibles subconsultas innecesarias
// ❌ No aprovecha índices óptimamente
```

**✅ Con Modo Lazy:**
```php
// El planificador optimiza automáticamente los JOINs
$users = $orm->table('users')
    ->lazy()
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->where('users.active', '=', true)
    ->where('posts.published', '=', true)
    ->collect();

// Resultado: JOINs optimizados automáticamente
// El planificador puede reorganizar las operaciones para mejor rendimiento
```

### Ejemplo 3: Operaciones Complejas en Lote

**❌ Forma Tradicional:**
```php
// Múltiples consultas separadas
foreach ($userIds as $userId) {
    $user = $orm->table('users')->where('id', '=', $userId)->findOne();
    $posts = $orm->table('posts')->where('user_id', '=', $userId)->findAll();
    // Procesar cada usuario individualmente
}

// Problemas:
// ❌ N+1 problem
// ❌ Múltiples round-trips a la base de datos
// ❌ Muy ineficiente
```

**✅ Con Modo Lazy:**
```php
// Una sola consulta optimizada con todos los datos
$usersWithPosts = $orm->table('users')
    ->lazy()
    ->whereIn('id', $userIds)
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->collect();

// El planificador puede optimizar esta consulta para:
// ✅ Minimizar accesos a la base de datos
// ✅ Usar índices óptimamente
// ✅ Combinar operaciones eficientemente
```

### Ejemplo 4: Análisis de Rendimiento

```php
// Comparar rendimiento entre modo normal y lazy
$startTime = microtime(true);

// Consulta normal
$normalUsers = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->orderBy('created_at', 'desc')
    ->limit(100)
    ->getAll();

$normalTime = microtime(true) - $startTime;

$startTime = microtime(true);

// Consulta lazy
$lazyUsers = $orm->table('users')
    ->lazy()
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->orderBy('created_at', 'desc')
    ->limit(100)
    ->collect();

$lazyTime = microtime(true) - $startTime;

echo "Tiempo normal: {$normalTime}s\n";
echo "Tiempo lazy: {$lazyTime}s\n";
echo "Mejora: " . round(($normalTime - $lazyTime) / $normalTime * 100, 2) . "%\n";
```

---

## 🔍 Depuración y Análisis

### Usando `explain()` para Entender Optimizaciones

```php
// Ver cómo VersaORM optimiza tu consulta
$plan = $orm->table('users')
    ->lazy()
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->orderBy('users.created_at', 'desc')
    ->explain();

print_r($plan);

// Salida ejemplo:
// Array
// (
//     [query_type] => optimized_select
//     [optimization_level] => high
//     [optimizations_applied] => Array
//         (
//             [0] => combined_where_clauses
//             [1] => optimized_join_order
//             [2] => index_usage_optimization
//         )
//     [estimated_execution_time] => 0.003
//     [final_sql] => SELECT users.*, profiles.* FROM users
//                    JOIN profiles ON users.id = profiles.user_id
//                    WHERE users.status = ? AND users.age >= ?
//                    ORDER BY users.created_at DESC
// )
```

### Modo Debug para Desarrollo

```php
// Activar logs detallados para ver las optimizaciones
$orm->config(['debug' => true]);

$users = $orm->table('users')
    ->lazy()
    ->where('status', '=', 'active')
    ->collect();

// Los logs mostrarán:
// - Operaciones acumuladas
// - Optimizaciones aplicadas
// - SQL final generado
// - Tiempo de ejecución
```

---

## ⚠️ Cuándo Usar el Modo Lazy

### ✅ Ideal para:

- **Consultas complejas** con múltiples WHERE, JOINs u ORDER BY
- **Operaciones en lote** con muchos registros
- **APIs de alto rendimiento** donde cada millisegundo cuenta
- **Consultas dinámicas** construidas condicionalmente
- **Reportes y analytics** con operaciones complejas

### ❌ No necesario para:

- **Consultas muy simples** (ej: `SELECT * FROM users WHERE id = 1`)
- **Inserciones/actualizaciones individuales**
- **Casos donde necesitas control granular** del SQL exacto

---

## 🎁 Beneficios del Modo Lazy

1. **🚀 Rendimiento Superior**: Consultas optimizadas automáticamente
2. **🧠 Inteligencia Automática**: El planificador toma las mejores decisiones
3. **💡 Fácil de Usar**: Solo añade `->lazy()` y `->collect()`
4. **🔍 Transparente**: Puedes ver las optimizaciones con `explain()`
5. **⚡ Menos Carga en la DB**: Reduce round-trips y optimiza el uso de recursos

---

## 🚀 Próximos Pasos

- Lee sobre [Query Builder](./02-query-builder.md) para entender las operaciones base
- Explora [Operaciones en Lote](./03-batch-operations.md) para casos de uso avanzados
- Revisa [Tipado Fuerte](./06-strong-typing-schema-validation.md) para validaciones automáticas

¡El Modo Lazy convierte VersaORM en el ORM más rápido y eficiente de PHP! 🎯
