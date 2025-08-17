# ⚠️ Nota Modo PHP / PDO
Estas características avanzadas se ejecutan hoy a través de PDO. Las optimizaciones internas adicionales del núcleo nativo se aplicarán automáticamente más adelante.

# 🚀 Funcionalidades SQL Avanzadas - VersaORM

¡Descubre las capacidades SQL más avanzadas de VersaORM! Esta guía te muestra cómo aprovechar funciones SQL complejas de manera fácil y segura usando el QueryBuilder.

> 🌟 **¿Eres nuevo con SQL avanzado?** No te preocupes, mostramos cada función con ejemplos simples de **SQL tradicional vs VersaORM**, para que veas la diferencia.

## 🤔 ¿Por qué Usar Funcionalidades SQL Avanzadas?

Las funcionalidades SQL avanzadas te permiten realizar análisis complejos, optimizar consultas y trabajar con datos de manera más eficiente. VersaORM las hace accesibles sin la complejidad habitual del SQL crudo.

### 🔄 La Diferencia es Espectacular

**❌ ANTES (SQL tradicional - complejo y propenso a errores):**
```sql
-- Window function manual y complicada
SELECT
    name,
    salary,
    department,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as dept_rank
FROM employees
WHERE salary > 50000;

-- CTE recursivo complejo
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 0 as level
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    JOIN employee_hierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM employee_hierarchy ORDER BY level, name;
```

**✅ DESPUÉS (VersaORM - fácil y potente):**
```php
// Window function simple y legible
$rankings = $orm->table('employees')
    ->where('salary', '>', 50000)
    ->windowFunction(
        'row_number',           // Función
        'salary',               // Columna
        [],                     // Opciones
        ['department'],         // PARTITION BY
        [['column' => 'salary', 'direction' => 'DESC']], // ORDER BY
        'dept_rank'             // Alias
    );

// CTE recursivo intuitivo
$hierarchy = $orm->table('employees')->withCte(
    [
        'employee_hierarchy' => [
            'query' => 'SELECT id, name, manager_id, 0 as level
                       FROM employees WHERE manager_id IS NULL
                       UNION ALL
                       SELECT e.id, e.name, e.manager_id, eh.level + 1
                       FROM employees e
                       JOIN employee_hierarchy eh ON e.manager_id = eh.id',
            'bindings' => []
        ]
    ],
    'SELECT * FROM employee_hierarchy ORDER BY level, name'
);
```

---

## 📚 Tabla de Contenidos

1. [🪟 Funciones de Ventana (Window Functions)](#funciones-de-ventana)
2. [🔗 CTEs (Common Table Expressions)](#ctes-common-table-expressions)
3. [🔀 Operaciones UNION](#operaciones-union)
4. [📊 Agregaciones Avanzadas](#agregaciones-avanzadas)
5. [🗂️ Operaciones JSON](#operaciones-json)
6. [🔍 Búsqueda de Texto Completo](#búsqueda-de-texto-completo)
7. [⚙️ Características Específicas del Motor](#características-específicas-del-motor)
8. [🔒 Validaciones de Seguridad](#validaciones-de-seguridad)
9. [💡 Ejemplos de Uso Completos](#ejemplos-de-uso-completos)

---

## 🪟 Funciones de Ventana

Las funciones de ventana permiten realizar cálculos sobre un conjunto de filas relacionadas con la fila actual, manteniendo el detalle de cada fila (a diferencia de GROUP BY).

### 🎯 ¿Cuándo usar funciones de ventana?

- Ranking de empleados por departamento
- Comparar valores con registros anteriores/siguientes
- Calcular totales acumulativos
- Análisis de tendencias y patrones

### 🔧 Funciones Soportadas

- `ROW_NUMBER()`: Asigna un número secuencial a las filas
- `RANK()`: Asigna un ranking con espacios para empates
- `DENSE_RANK()`: Asigna un ranking sin espacios para empates
- `LAG()`: Accede a datos de filas anteriores
- `LEAD()`: Accede a datos de filas posteriores
- `FIRST_VALUE()` / `LAST_VALUE()`: Primer/último valor en la ventana
- `NTILE()`: Divide las filas en grupos numerados

### 📝 Sintaxis VersaORM

```php
$result = $queryBuilder->windowFunction(
    string $function,           // Nombre de la función
    string $column = '*',       // Columna a procesar
    array $args = [],          // Argumentos específicos (LAG/LEAD offset, etc.)
    array $partitionBy = [],    // Columnas para PARTITION BY
    array $orderBy = [],        // Ordenamiento dentro de la ventana
    string $alias = 'window_result' // Alias para el resultado
);
```

### 💡 Ejemplos Comparativos

#### ROW_NUMBER - Numeración de filas

**❌ SQL tradicional:**
```sql
-- Difícil de leer y mantener
SELECT
    id,
    name,
    salary,
    department,
    ROW_NUMBER() OVER (
        PARTITION BY department
        ORDER BY salary DESC
    ) as dept_rank
FROM employees
WHERE salary > 50000
ORDER BY department, dept_rank;
```

**✅ VersaORM:**
```php
// Claro, legible y reutilizable
$rankings = $orm->table('employees')
    ->where('salary', '>', 50000)
    ->windowFunction(
        'row_number',                                    // Función
        '*',                                             // Columna
        [],                                              // Sin argumentos adicionales
        ['department'],                                  // PARTITION BY department
        [['column' => 'salary', 'direction' => 'DESC']], // ORDER BY salary DESC
        'dept_rank'                                      // Alias del resultado
    );

// Resultado automáticamente ordenado por department, dept_rank
```

#### LAG - Comparar con valores anteriores

**❌ SQL tradicional:**
```sql
-- Sintaxis compleja para analistas
SELECT
    month,
    sales,
    LAG(sales, 1, 0) OVER (ORDER BY month) as previous_month_sales,
    sales - LAG(sales, 1, 0) OVER (ORDER BY month) as growth
FROM monthly_sales
ORDER BY month;
```

**✅ VersaORM:**
```php
// Intuitivo para cualquier desarrollador PHP
$salesTrends = $orm->table('monthly_sales')
    ->windowFunction(
        'lag',                                  // Función LAG
        'sales',                               // Columna a comparar
        ['offset' => 1, 'default_value' => 0], // LAG(sales, 1, 0)
        [],                                    // Sin partición
        [['column' => 'month', 'direction' => 'ASC']], // ORDER BY month
        'previous_month_sales'                 // Alias
    );

// Para calcular crecimiento, puedes usar una consulta adicional
// o raw SQL en el select
```

#### RANK - Ranking con empates

**❌ SQL tradicional:**
```sql
-- Propenso a errores de sintaxis
SELECT
    name,
    department,
    performance_score,
    RANK() OVER (
        PARTITION BY department
        ORDER BY performance_score DESC
    ) as performance_rank
FROM employees
WHERE performance_score IS NOT NULL;
```

**✅ VersaORM:**
```php
// Sin errores de sintaxis, con validación automática
$performanceRanks = $orm->table('employees')
    ->whereNotNull('performance_score')
    ->windowFunction(
        'rank',                                               // Función RANK
        'performance_score',                                  // Columna a rankear
        [],                                                   // Sin argumentos
        ['department'],                                       // PARTITION BY department
        [['column' => 'performance_score', 'direction' => 'DESC']], // ORDER BY performance_score DESC
        'performance_rank'                                    // Alias
    );

// Automáticamente protegido contra inyección SQL
```

---

## 🔗 CTEs (Common Table Expressions)

Los CTEs son subconsultas temporales que se pueden referenciar múltiples veces en la consulta principal. Piensa en ellos como "vistas temporales" que existen solo durante la ejecución de tu consulta.

### 🎯 ¿Cuándo usar CTEs?

- Simplificar consultas complejas dividiéndolas en partes
- Reutilizar la misma subconsulta múltiples veces
- Crear jerarquías recursivas (empleados-managers, categorías anidadas)
- Mejorar la legibilidad del código

### 📝 Sintaxis VersaORM

```php
$result = $queryBuilder->withCte(
    array $ctes,                // Array de definiciones CTE
    string $mainQuery,          // Consulta principal
    array $mainQueryBindings = []// Parámetros para la consulta principal
);
```

### 🏗️ Estructura de CTE

```php
$ctes = [
    'nombre_cte' => [
        'query' => 'SELECT ...',      // SQL de la subconsulta
        'bindings' => [...]           // Parámetros para la subconsulta
    ]
];
```

### 💡 Ejemplos Comparativos

#### CTE Simple - Filtrar y reutilizar

**❌ SQL tradicional:**
```sql
-- Repetir la misma subconsulta múltiples veces
SELECT department, COUNT(*) as high_earner_count
FROM (
    SELECT * FROM employees WHERE salary > 80000
) high_earners
GROUP BY department

UNION ALL

SELECT 'TOTAL' as department, COUNT(*) as high_earner_count
FROM (
    SELECT * FROM employees WHERE salary > 80000  -- ¡Duplicado!
) high_earners;
```

**✅ VersaORM:**
```php
// Definir una vez, usar múltiples veces
$ctes = [
    'high_earners' => [
        'query' => 'SELECT * FROM employees WHERE salary > ?',
        'bindings' => [80000]
    ]
];

$result = $orm->table('employees')->withCte(
    $ctes,
    'SELECT department, COUNT(*) as count
     FROM high_earners
     GROUP BY department'
);

// Sin duplicación, más fácil de mantener
```

#### CTE Recursivo - Jerarquía de empleados

**❌ SQL tradicional:**
```sql
-- Sintaxis recursiva compleja y difícil de entender
WITH RECURSIVE employee_hierarchy AS (
    -- Caso base: empleados sin manager
    SELECT id, name, manager_id, 0 as level,
           CAST(name AS CHAR(1000)) as path
    FROM employees
    WHERE manager_id IS NULL

    UNION ALL

    -- Caso recursivo: empleados con manager
    SELECT e.id, e.name, e.manager_id, eh.level + 1,
           CONCAT(eh.path, ' -> ', e.name) as path
    FROM employees e
    INNER JOIN employee_hierarchy eh ON e.manager_id = eh.id
    WHERE eh.level < 10  -- Prevenir recursión infinita
)
SELECT * FROM employee_hierarchy ORDER BY level, name;
```

**✅ VersaORM:**
```php
// Recursión clara y protegida automáticamente
$ctes = [
    'employee_hierarchy' => [
        'query' => '
            SELECT id, name, manager_id, 0 as level
            FROM employees
            WHERE manager_id IS NULL
            UNION ALL
            SELECT e.id, e.name, e.manager_id, eh.level + 1
            FROM employees e
            JOIN employee_hierarchy eh ON e.manager_id = eh.id
            WHERE eh.level < 10',  // Protección automática contra recursión infinita
        'bindings' => []
    ]
];

$hierarchy = $orm->table('employees')->withCte(
    $ctes,
    'SELECT * FROM employee_hierarchy ORDER BY level, name'
);

// VersaORM maneja automáticamente la seguridad y optimización
```

#### Múltiples CTEs - Análisis complejo

**❌ SQL tradicional:**
```sql
-- Múltiples WITH difíciles de seguir
WITH top_performers AS (
    SELECT employee_id, SUM(sales_amount) as total_sales
    FROM sales
    WHERE sale_date >= '2024-01-01'
    GROUP BY employee_id
    HAVING SUM(sales_amount) > 100000
),
recent_hires AS (
    SELECT id, name, department, hire_date
    FROM employees
    WHERE hire_date >= '2024-01-01'
),
department_stats AS (
    SELECT department,
           COUNT(*) as employee_count,
           AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
)
SELECT rh.name, rh.department, ds.avg_salary, tp.total_sales
FROM recent_hires rh
LEFT JOIN top_performers tp ON rh.id = tp.employee_id
JOIN department_stats ds ON rh.department = ds.department
ORDER BY tp.total_sales DESC NULLS LAST;
```

**✅ VersaORM:**
```php
// Múltiples CTEs organizados y legibles
$ctes = [
    'top_performers' => [
        'query' => 'SELECT employee_id, SUM(sales_amount) as total_sales
                   FROM sales
                   WHERE sale_date >= ?
                   GROUP BY employee_id
                   HAVING SUM(sales_amount) > ?',
        'bindings' => ['2024-01-01', 100000]
    ],
    'recent_hires' => [
        'query' => 'SELECT id, name, department, hire_date
                   FROM employees
                   WHERE hire_date >= ?',
        'bindings' => ['2024-01-01']
    ],
    'department_stats' => [
        'query' => 'SELECT department,
                          COUNT(*) as employee_count,
                          AVG(salary) as avg_salary
                   FROM employees
                   GROUP BY department',
        'bindings' => []
    ]
];

$analysis = $orm->table('employees')->withCte(
    $ctes,
    'SELECT rh.name, rh.department, ds.avg_salary, tp.total_sales
     FROM recent_hires rh
     LEFT JOIN top_performers tp ON rh.id = tp.employee_id
     JOIN department_stats ds ON rh.department = ds.department
     ORDER BY tp.total_sales DESC'
);

// Cada CTE es independiente y reutilizable
// Parámetros seguros automáticamente
```

---

## 🔀 Operaciones UNION

Las operaciones UNION combinan resultados de múltiples consultas en un solo conjunto de resultados. Es como "apilar" tablas que tienen la misma estructura de columnas.

### 🎯 ¿Cuándo usar UNION?

- Combinar datos de tablas similares (ej: empleados_2023 + empleados_2024)
- Unir diferentes tipos de entidades con campos comunes
- Crear reportes consolidados
- Migración de datos entre tablas

### 🔧 Operaciones de Conjuntos Disponibles

VersaORM en modo PDO soporta varias operaciones de conjuntos. El soporte depende del driver:

| Operación        | Descripción                                                     | MySQL | PostgreSQL | SQLite |
|------------------|-----------------------------------------------------------------|:-----:|:----------:|:------:|
| UNION            | Combina conjuntos eliminando duplicados                         |  ✔    |     ✔      |   ✔    |
| UNION ALL        | Combina conjuntos manteniendo duplicados                        |  ✔    |     ✔      |   ✔    |
| INTERSECT        | Intersección (elimina duplicados)                               |  ✖    |     ✔      |   ✖*   |
| INTERSECT ALL    | Intersección preservando multiplicidades mínimas                |  ✖    |     ✔      |   ✖*   |
| EXCEPT           | Diferencia (A \ B) eliminando duplicados                        |  ✖    |     ✔      |   ✖*   |
| EXCEPT ALL       | Diferencia preservando multiplicidades residuales               |  ✖    |     ✔      |   ✖*   |

(*SQLite puede soportar INTERSECT/EXCEPT en determinadas versiones, pero se deshabilitan aquí para maximizar compatibilidad; se lanza VersaORMException.)

Notas:
- Usa `$qb->union($queries, true)` para UNION ALL.
- Usa `$qb->intersect($otherQb, bool $all = false)` y `$qb->except($otherQb, bool $all = false)` solo en PostgreSQL.
- Intentar INTERSECT/EXCEPT en drivers no soportados lanza `VersaORMException`.

### 📝 Sintaxis VersaORM

```php
// UNION / UNION ALL
$rows = $qb->union([
    ['sql' => 'SELECT id FROM table_a', 'bindings' => []],
    ['sql' => 'SELECT id FROM table_b', 'bindings' => []],
], false); // false => UNION (sin duplicados)

// INTERSECT (PostgreSQL)
$rows = $qbA->intersect($qbB);            // INTERSECT
$rows = $qbA->intersect($qbB, true);      // INTERSECT ALL

// EXCEPT (PostgreSQL)
$rows = $qbA->except($qbB);               // EXCEPT
$rows = $qbA->except($qbB, true);         // EXCEPT ALL
```

---

### 📘 Más Recursos

Para comprender cómo VersaORM maneja y registra errores con metadatos enriquecidos revisa: [14-error-handling-logging.md](14-error-handling-logging.md).

### 💡 Ejemplos Comparativos

#### UNION Simple - Combinar tablas similares

**❌ SQL tradicional:**
```sql
-- Sintaxis verbosa y propensa a errores
SELECT name, email, 'employee' as type
FROM employees
WHERE status = 'active'
UNION
SELECT name, email, 'contractor' as type
FROM contractors
WHERE contract_end > CURDATE()
ORDER BY name;
```

**✅ VersaORM:**
```php
// Limpio y reutilizable
$queries = [
    [
        'sql' => 'SELECT name, email, "employee" as type FROM employees WHERE status = ?',
        'bindings' => ['active']
    ],
    [
        'sql' => 'SELECT name, email, "contractor" as type FROM contractors WHERE contract_end > CURDATE()',
        'bindings' => []
    ]
];

$allStaff = $orm->table('employees')->union($queries);
// Automáticamente ordenado y sin duplicados
```

#### UNION ALL - Performance mejorado

**❌ SQL tradicional:**
```sql
-- Cuando sabes que no hay duplicados, pero la sintaxis es la misma
SELECT product_name, price, 'current' as catalog
FROM products_2024
UNION ALL
SELECT product_name, price, 'archive' as catalog
FROM products_2023
ORDER BY price DESC
LIMIT 100;
```

**✅ VersaORM:**
```php
// Explícito sobre el comportamiento
$productQueries = [
    [
        'sql' => 'SELECT product_name, price, "current" as catalog FROM products_2024',
        'bindings' => []
    ],
    [
        'sql' => 'SELECT product_name, price, "archive" as catalog FROM products_2023',
        'bindings' => []
    ]
];

$allProducts = $orm->table('products_2024')->union($productQueries, true); // true = UNION ALL
// Más rápido porque no elimina duplicados
```

#### UNION con QueryBuilder - Método fluido

**❌ SQL tradicional:**
```sql
-- Difícil de construir dinámicamente
SELECT u.name, u.email, 'premium' as tier
FROM users u
JOIN subscriptions s ON u.id = s.user_id
WHERE s.plan = 'premium' AND s.status = 'active'
UNION
SELECT u.name, u.email, 'trial' as tier
FROM users u
JOIN trials t ON u.id = t.user_id
WHERE t.expires_at > NOW();
```

**✅ VersaORM:**
```php
// Construcción dinámica y fluida
$premiumUsers = $orm->table('users')
    ->select(['users.name', 'users.email', '"premium" as tier'])
    ->join('subscriptions', 'users.id', '=', 'subscriptions.user_id')
    ->where('subscriptions.plan', '=', 'premium')
    ->where('subscriptions.status', '=', 'active');

$trialUsers = $orm->table('users')
    ->select(['users.name', 'users.email', '"trial" as tier'])
    ->join('trials', 'users.id', '=', 'trials.user_id')
    ->whereRaw('trials.expires_at > NOW()');

// Combinar usando QueryBuilder directamente
$allUsers = $premiumUsers->union($trialUsers);

// O usando callable para mayor flexibilidad
$allUsers = $orm->table('users')->union(function($query) {
    $query->select(['name', 'email', '"trial" as tier'])
          ->join('trials', 'users.id', '=', 'trials.user_id')
          ->whereRaw('trials.expires_at > NOW()');
});
```

#### INTERSECT - Solo registros comunes

**❌ SQL tradicional:**
```sql
-- No todos los motores soportan INTERSECT
SELECT email FROM newsletter_subscribers
INTERSECT
SELECT email FROM customers
WHERE purchase_date >= '2024-01-01';
```

**✅ VersaORM:**
```php
// Funciona en todos los motores compatibles
$subscriberQuery = $orm->table('newsletter_subscribers')
    ->select(['email']);

$customerQuery = $orm->table('customers')
    ->select(['email'])
    ->where('purchase_date', '>=', '2024-01-01');

$subscribedCustomers = $subscriberQuery->intersect($customerQuery);
// Solo emails que están en ambas tablas
```

#### EXCEPT - Exclusión de registros

**❌ SQL tradicional:**
```sql
-- Sintaxis compleja y limitada
SELECT email FROM all_users
EXCEPT
SELECT email FROM unsubscribed_users
WHERE unsubscribed_at >= '2024-01-01';
```

**✅ VersaORM:**
```php
// Claro y expresivo
$allUsersQuery = $orm->table('all_users')
    ->select(['email']);

$unsubscribedQuery = $orm->table('unsubscribed_users')
    ->select(['email'])
    ->where('unsubscribed_at', '>=', '2024-01-01');

$activeSubscribers = $allUsersQuery->except($unsubscribedQuery);
// Solo usuarios que NO se han desuscrito
```

---

## 📊 Agregaciones Avanzadas

Las agregaciones avanzadas van más allá del simple COUNT, SUM, AVG. Incluyen funciones estadísticas especializadas para análisis de datos complejos.

### 🎯 ¿Cuándo usar agregaciones avanzadas?

- Análisis estadístico de datos (percentiles, varianza)
- Reportes financieros y KPIs
- Análisis de rendimiento y métricas
- Concatenación de datos agrupados

### 🔧 Funciones Soportadas

- `group_concat` / `string_agg`: Concatena valores en una cadena
- `percentile`: Calcula percentiles específicos (P50, P75, P90, P95, P99)
- `median`: Calcula la mediana (equivale al percentil 50)
- `variance`: Calcula la varianza estadística
- `stddev`: Calcula la desviación estándar

### 📝 Sintaxis VersaORM

```php
$result = $queryBuilder->advancedAggregation(
    string $type,               // Tipo de agregación
    string $column,             // Columna a agregar
    array $options = [],        // Opciones específicas
    array $groupBy = [],        // Columnas GROUP BY
    string $alias = ''          // Alias del resultado
);
```

### 💡 Ejemplos Comparativos

#### GROUP_CONCAT - Concatenar valores agrupados

**❌ SQL tradicional:**
```sql
-- Sintaxis diferente entre motores
-- MySQL:
SELECT department,
       GROUP_CONCAT(name SEPARATOR '; ') as employee_names
FROM employees
GROUP BY department;

-- PostgreSQL:
SELECT department,
       STRING_AGG(name, '; ' ORDER BY name) as employee_names
FROM employees
GROUP BY department;
```

**✅ VersaORM:**
```php
// Funciona igual en todos los motores
$departmentLists = $orm->table('employees')
    ->advancedAggregation(
        'group_concat',              // Función universal
        'name',                      // Columna a concatenar
        ['separator' => '; '],       // Separador personalizado
        ['department'],              // GROUP BY department
        'employee_names'             // Alias
    );

// VersaORM traduce automáticamente a la sintaxis correcta del motor
```

#### Percentiles - Análisis estadístico

**❌ SQL tradicional:**
```sql
-- Sintaxis compleja y diferente por motor
-- MySQL 8.0+:
SELECT department,
       PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY salary) as p50_salary,
       PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY salary) as p75_salary,
       PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY salary) as p90_salary
FROM employees
GROUP BY department;

-- PostgreSQL:
SELECT department,
       PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY salary) as median_salary,
       PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY salary) as p75_salary
FROM employees
GROUP BY department;
```

**✅ VersaORM:**
```php
// Consistente y fácil para cualquier percentil
$salaryP75 = $orm->table('employees')
    ->advancedAggregation(
        'percentile',                // Función
        'salary',                    // Columna
        ['percentile' => 0.75],      // Percentil 75 (Q3)
        ['department'],              // GROUP BY
        'p75_salary'                 // Alias
    );

$salaryP90 = $orm->table('employees')
    ->advancedAggregation(
        'percentile',
        'salary',
        ['percentile' => 0.90],      // Percentil 90
        ['department'],
        'p90_salary'
    );

// Múltiples percentiles en consultas separadas para claridad
```

#### Mediana - Valor central

**❌ SQL tradicional:**
```sql
-- Diferentes enfoques según el motor
-- Algunos motores no tienen MEDIAN nativo
SELECT department,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) as median_salary,
       AVG(salary) as avg_salary
FROM employees
GROUP BY department;
```

**✅ VersaORM:**
```php
// Función dedicada, más expresiva
$medianSalaries = $orm->table('employees')
    ->advancedAggregation(
        'median',                    // Más claro que percentile(0.5)
        'salary',                    // Columna
        [],                          // Sin opciones adicionales
        ['department'],              // GROUP BY
        'median_salary'              // Alias
    );

// Fácil de leer y entender la intención
```

#### Varianza y Desviación Estándar

**❌ SQL tradicional:**
```sql
-- Funciones específicas del motor con nombres diferentes
-- MySQL: VAR_POP, VAR_SAMP, STDDEV_POP, STDDEV_SAMP
-- PostgreSQL: VAR_POP, VAR_SAMP, STDDEV_POP, STDDEV_SAMP
SELECT department,
       VAR_POP(salary) as salary_variance,
       STDDEV_POP(salary) as salary_stddev,
       AVG(salary) as avg_salary
FROM employees
WHERE salary IS NOT NULL
GROUP BY department
HAVING COUNT(*) >= 10;  -- Solo departamentos con suficientes datos
```

**✅ VersaORM:**
```php
// Funciones normalizadas
$salaryVariance = $orm->table('employees')
    ->whereNotNull('salary')
    ->having('COUNT(*)', '>=', 10)  // Solo departamentos grandes
    ->advancedAggregation(
        'variance',                  // Función normalizada
        'salary',                   // Columna
        [],                         // Sin opciones
        ['department'],             // GROUP BY
        'salary_variance'           // Alias
    );

$salaryStdDev = $orm->table('employees')
    ->whereNotNull('salary')
    ->having('COUNT(*)', '>=', 10)
    ->advancedAggregation(
        'stddev',                   // Desviación estándar
        'salary',
        [],
        ['department'],
        'salary_stddev'
    );

// Consistente entre motores, sin preocuparse por VAR_POP vs VAR_SAMP
```

#### Ejemplo Real: Dashboard de Métricas de Ventas

**❌ SQL tradicional:**
```sql
-- Consulta compleja difícil de mantener
SELECT
    region,
    COUNT(*) as total_sales,
    SUM(amount) as total_revenue,
    AVG(amount) as avg_sale,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY amount) as median_sale,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY amount) as p95_sale,
    STDDEV_POP(amount) as revenue_volatility,
    GROUP_CONCAT(DISTINCT salesperson ORDER BY salesperson SEPARATOR ', ') as salespeople
FROM sales
WHERE sale_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY region
HAVING COUNT(*) >= 5
ORDER BY total_revenue DESC;
```

**✅ VersaORM:**
```php
// Análisis step-by-step, más mantenible
$baseQuery = $orm->table('sales')
    ->where('sale_date', '>=', date('Y-m-d', strtotime('-30 days')))
    ->having('COUNT(*)', '>=', 5);

// Mediana de ventas
$medianSales = $baseQuery->advancedAggregation(
    'median', 'amount', [], ['region'], 'median_sale'
);

// Percentil 95 (top performers threshold)
$p95Sales = $baseQuery->advancedAggregation(
    'percentile', 'amount', ['percentile' => 0.95], ['region'], 'p95_sale'
);

// Volatilidad (desviación estándar)
$volatility = $baseQuery->advancedAggregation(
    'stddev', 'amount', [], ['region'], 'revenue_volatility'
);

// Lista de vendedores
$salespeople = $baseQuery->advancedAggregation(
    'group_concat', 'salesperson', ['separator' => ', '], ['region'], 'salespeople'
);

// Cada métrica es independiente y reutilizable
// Fácil agregar/quitar métricas según necesidades del negocio
```
    [],
    ['department'],
    'salary_stddev'
);
```

---

## 🗂️ Operaciones JSON

Las operaciones JSON permiten trabajar con datos JSON almacenados en columnas de base de datos. Son especialmente útiles para datos semiestructurados y configuraciones flexibles.

### 🎯 ¿Cuándo usar operaciones JSON?

- Almacenar configuraciones de usuario flexibles
- Metadatos de productos con atributos variables
- Logs estructurados y telemetría
- APIs que necesitan campos dinámicos

### 🔧 Operaciones Soportadas

- `extract`: Extrae valores de rutas JSON específicas
- `contains`: Verifica si contiene un valor específico
- `search`: Busca valores en rutas específicas
- `array_length`: Obtiene la longitud de arrays JSON
- `type`: Obtiene el tipo de un valor JSON
- `keys`: Lista las claves de objetos JSON

### 📝 Sintaxis VersaORM

```php
$result = $queryBuilder->jsonOperation(
    string $operation,          // Tipo de operación JSON
    string $column,             // Columna que contiene JSON
    string $path = '',          // Ruta JSON (ej: '$.user.name')
    mixed $value = null         // Valor para comparaciones/búsquedas
);
```

### 💡 Ejemplos Comparativos

#### Extraer Valores JSON

**❌ SQL tradicional:**
```sql
-- Sintaxis diferente entre motores
-- MySQL:
SELECT id, name,
       JSON_EXTRACT(profile, '$.age') as age,
       JSON_EXTRACT(profile, '$.skills[0]') as first_skill
FROM users
WHERE JSON_EXTRACT(profile, '$.active') = true;

-- PostgreSQL:
SELECT id, name,
       profile->>'age' as age,
       profile->'skills'->0 as first_skill
FROM users
WHERE (profile->>'active')::boolean = true;
```

**✅ VersaORM:**
```php
// Sintaxis universal para todos los motores
$userAges = $orm->table('users')
    ->jsonOperation(
        'extract',              // Operación
        'profile',              // Columna JSON
        '$.age',               // Ruta JSON
        null                   // Sin valor de comparación
    );

$firstSkills = $orm->table('users')
    ->jsonOperation(
        'extract',
        'profile',
        '$.skills[0]',         // Array index notation
        null
    );

// VersaORM traduce automáticamente a la sintaxis del motor
```

#### Buscar Contenido en JSON

**❌ SQL tradicional:**
```sql
-- Búsqueda compleja en arrays JSON
-- MySQL:
SELECT * FROM products
WHERE JSON_CONTAINS(features, '"waterproof"', '$.tags')
   OR JSON_SEARCH(features, 'one', 'PHP', NULL, '$.technologies[*]') IS NOT NULL;

-- PostgreSQL:
SELECT * FROM products
WHERE features->'tags' ? 'waterproof'
   OR features->'technologies' @> '"PHP"';
```

**✅ VersaORM:**
```php
// Búsqueda consistente y legible
$waterproofProducts = $orm->table('products')
    ->jsonOperation(
        'contains',             // Verificar si contiene
        'features',             // Columna JSON
        '$.tags',              // Ruta donde buscar
        'waterproof'           // Valor a buscar
    );

$phpProducts = $orm->table('products')
    ->jsonOperation(
        'contains',
        'features',
        '$.technologies',      // Array de tecnologías
        'PHP'                  // Tecnología específica
    );

// Búsqueda más específica con search
$reactProducts = $orm->table('products')
    ->jsonOperation(
        'search',              // Búsqueda más precisa
        'features',
        '$.technologies[*]',   // Wildcard en array
        'React'
    );
```

#### Longitud de Arrays JSON

**❌ SQL tradicional:**
```sql
-- Contar elementos en arrays JSON
-- MySQL:
SELECT user_id,
       JSON_LENGTH(skills, '$.programming_languages') as lang_count,
       JSON_LENGTH(skills, '$.certifications') as cert_count
FROM user_profiles
WHERE JSON_LENGTH(skills, '$.programming_languages') >= 3;

-- PostgreSQL:
SELECT user_id,
       jsonb_array_length(skills->'programming_languages') as lang_count,
       jsonb_array_length(skills->'certifications') as cert_count
FROM user_profiles
WHERE jsonb_array_length(skills->'programming_languages') >= 3;
```

**✅ VersaORM:**
```php
// Contar elementos de forma universal
$polyglotDevelopers = $orm->table('user_profiles')
    ->jsonOperation(
        'array_length',         // Contar elementos
        'skills',               // Columna JSON
        '$.programming_languages' // Ruta al array
    );

// Filtrar por número de habilidades
$experiencedDevs = $orm->table('user_profiles')
    ->whereRaw('JSON_LENGTH(skills, "$.programming_languages") >= 3')
    ->jsonOperation(
        'array_length',
        'skills',
        '$.certifications'
    );

// Para consultas complejas, combinar con where normal
```

#### Ejemplo Real: Sistema de Configuración de Usuario

**❌ SQL tradicional:**
```sql
-- Consulta compleja para configuraciones
SELECT
    u.id,
    u.email,
    JSON_EXTRACT(u.preferences, '$.theme') as theme,
    JSON_EXTRACT(u.preferences, '$.notifications.email') as email_notifications,
    JSON_LENGTH(u.preferences, '$.dashboard_widgets') as widget_count,
    CASE
        WHEN JSON_CONTAINS(u.preferences, '"advanced"', '$.features')
        THEN 'advanced_user'
        ELSE 'basic_user'
    END as user_type
FROM users u
WHERE JSON_EXTRACT(u.preferences, '$.active') = true
  AND JSON_LENGTH(u.preferences, '$.dashboard_widgets') > 0
ORDER BY user_type, email;
```

**✅ VersaORM:**
```php
// Configuraciones de usuario paso a paso
$baseQuery = $orm->table('users')
    ->where('active', '=', true);

// Tema del usuario
$userThemes = $baseQuery->jsonOperation(
    'extract',
    'preferences',
    '$.theme'
);

// Configuración de notificaciones
$emailNotifications = $baseQuery->jsonOperation(
    'extract',
    'preferences',
    '$.notifications.email'
);

// Número de widgets en dashboard
$widgetCounts = $baseQuery->jsonOperation(
    'array_length',
    'preferences',
    '$.dashboard_widgets'
);

// Usuarios con características avanzadas
$advancedUsers = $baseQuery->jsonOperation(
    'contains',
    'preferences',
    '$.features',
    'advanced'
);

// Configuración completa para un usuario específico
$userConfig = $orm->table('users')
    ->where('id', '=', $userId)
    ->select(['id', 'email'])
    ->first();

// Extraer configuraciones específicas por separado para mayor claridad
$theme = $orm->table('users')
    ->where('id', '=', $userId)
    ->jsonOperation('extract', 'preferences', '$.theme');

$notifications = $orm->table('users')
    ->where('id', '=', $userId)
    ->jsonOperation('extract', 'preferences', '$.notifications');
```

#### Validación y Mantenimiento de JSON

**❌ SQL tradicional:**
```sql
-- Verificar integridad de datos JSON
SELECT COUNT(*) as invalid_profiles
FROM users
WHERE preferences IS NOT NULL
  AND JSON_VALID(preferences) = 0;

-- Usuarios con configuraciones incompletas
SELECT id, email
FROM users
WHERE JSON_EXTRACT(preferences, '$.theme') IS NULL
   OR JSON_EXTRACT(preferences, '$.language') IS NULL;
```

**✅ VersaORM:**
```php
// Verificación de integridad JSON
$usersWithInvalidJSON = $orm->table('users')
    ->whereNotNull('preferences')
    ->whereRaw('JSON_VALID(preferences) = 0')  // Para motores que soportan JSON_VALID
    ->count();

// Configuraciones incompletas usando operaciones JSON
$incompleteConfigs = $orm->table('users')
    ->jsonOperation('extract', 'preferences', '$.theme')
    ->whereNull('extracted_value')  // Resultado de la extracción
    ->union(
        $orm->table('users')
            ->jsonOperation('extract', 'preferences', '$.language')
            ->whereNull('extracted_value')
    );

// Estadísticas de tipos de configuración
$themeStats = $orm->table('users')
    ->jsonOperation('extract', 'preferences', '$.theme')
    ->groupBy('extracted_theme')
    ->selectRaw('extracted_theme as theme, COUNT(*) as user_count')
    ->orderBy('user_count', 'DESC')
    ->get();
```

---

## 🔍 Búsqueda de Texto Completo

La búsqueda de texto completo permite encontrar contenido de manera inteligente en múltiples columnas de texto, usando capacidades avanzadas del motor de base de datos.

### 🎯 ¿Cuándo usar búsqueda de texto completo?

- Motores de búsqueda de contenido
- Búsqueda en documentos y artículos
- Sistemas de ayuda y FAQ
- E-commerce (búsqueda de productos)
- Análisis de sentimientos en comentarios

### 🔧 Características

- Búsqueda en múltiples columnas simultáneamente
- Relevancia automática de resultados
- Soporte para sinónimos y variaciones
- Búsqueda difusa (typos y aproximaciones)
- Ranking por relevancia

### 📝 Sintaxis VersaORM

```php
$result = $queryBuilder->fullTextSearch(
    array $columns,             // Columnas donde buscar
    string $searchTerm,         // Término a buscar
    array $options = []         // Opciones específicas del motor
);
```

### 💡 Ejemplos Comparativos

#### Búsqueda Básica en Múltiples Columnas

**❌ SQL tradicional:**
```sql
-- Búsqueda manual con LIKE (lenta e imprecisa)
SELECT * FROM articles
WHERE title LIKE '%database%'
   OR content LIKE '%database%'
   OR tags LIKE '%database%'
ORDER BY
    CASE
        WHEN title LIKE '%database%' THEN 1
        WHEN content LIKE '%database%' THEN 2
        ELSE 3
    END;

-- O usando FULLTEXT específico del motor (MySQL):
SELECT *, MATCH(title, content) AGAINST('database optimization' IN NATURAL LANGUAGE MODE) as relevance
FROM articles
WHERE MATCH(title, content) AGAINST('database optimization' IN NATURAL LANGUAGE MODE)
ORDER BY relevance DESC;
```

**✅ VersaORM:**
```php
// Búsqueda inteligente universal
$articles = $orm->table('articles')
    ->fullTextSearch(
        ['title', 'content', 'tags'],  // Columnas a buscar
        'database optimization'        // Término de búsqueda
    );

// VersaORM automáticamente:
// - Usa índices FULLTEXT si están disponibles
// - Ordena por relevancia
// - Maneja diferencias entre motores de BD
```

#### Búsqueda con Filtros Adicionales

**❌ SQL tradicional:**
```sql
-- Combinar fulltext con filtros normales
SELECT a.*, u.name as author_name,
       MATCH(a.title, a.content) AGAINST('machine learning' IN NATURAL LANGUAGE MODE) as score
FROM articles a
JOIN users u ON a.author_id = u.id
WHERE MATCH(a.title, a.content) AGAINST('machine learning' IN NATURAL LANGUAGE MODE)
  AND a.published_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
  AND a.category = 'technology'
  AND a.status = 'published'
ORDER BY score DESC, a.published_at DESC
LIMIT 20;
```

**✅ VersaORM:**
```php
// Búsqueda combinada con filtros
$recentMLArticles = $orm->table('articles')
    ->join('users', 'articles.author_id', '=', 'users.id')
    ->where('published_at', '>=', date('Y-m-d', strtotime('-30 days')))
    ->where('category', '=', 'technology')
    ->where('status', '=', 'published')
    ->fullTextSearch(
        ['title', 'content'],      // Columnas de búsqueda
        'machine learning'         // Término
    )
    ->limit(20);

// Filtros y búsqueda se combinan automáticamente
// Orden por relevancia preservado
```

#### Búsqueda con Opciones Avanzadas

**❌ SQL tradicional:**
```sql
-- Diferentes opciones según el motor
-- MySQL con modo boolean:
SELECT *, MATCH(title, content) AGAINST('+php +laravel -wordpress' IN BOOLEAN MODE) as relevance
FROM tutorials
WHERE MATCH(title, content) AGAINST('+php +laravel -wordpress' IN BOOLEAN MODE)
ORDER BY relevance DESC;

-- PostgreSQL con configuración específica:
SELECT *, ts_rank(to_tsvector('english', title || ' ' || content), plainto_tsquery('english', 'php laravel')) as rank
FROM tutorials
WHERE to_tsvector('english', title || ' ' || content) @@ plainto_tsquery('english', 'php laravel')
ORDER BY rank DESC;
```

**✅ VersaORM:**
```php
// Opciones avanzadas normalizadas
$phpTutorials = $orm->table('tutorials')
    ->fullTextSearch(
        ['title', 'content'],
        'php laravel',
        [
            'mode' => 'boolean',           // Para motores que lo soporten
            'language' => 'english',       // Idioma para stemming
            'min_relevance' => 0.1,        // Umbral mínimo de relevancia
            'boost_title' => 2.0           // Priorizar matches en título
        ]
    );

// Búsqueda con términos obligatorios y excluidos
$specificSearch = $orm->table('tutorials')
    ->fullTextSearch(
        ['title', 'content', 'tags'],
        '+php +laravel -wordpress',     // Sintaxis boolean
        ['mode' => 'boolean']
    );
```

#### Ejemplo Real: Motor de Búsqueda de E-commerce

**❌ SQL tradicional:**
```sql
-- Búsqueda compleja de productos
SELECT p.*,
       b.name as brand_name,
       c.name as category_name,
       MATCH(p.name, p.description, p.keywords) AGAINST('smartphone camera battery' IN NATURAL LANGUAGE MODE) as relevance,
       -- Boost para productos en oferta
       CASE WHEN p.discount > 0 THEN relevance * 1.5 ELSE relevance END as final_score
FROM products p
JOIN brands b ON p.brand_id = b.id
JOIN categories c ON p.category_id = c.id
WHERE MATCH(p.name, p.description, p.keywords) AGAINST('smartphone camera battery' IN NATURAL LANGUAGE MODE)
  AND p.active = 1
  AND p.stock > 0
  AND p.price BETWEEN 100 AND 1000
ORDER BY final_score DESC, p.rating DESC
LIMIT 50;
```

**✅ VersaORM:**
```php
// Motor de búsqueda modular y mantenible
$productSearch = $orm->table('products')
    ->join('brands', 'products.brand_id', '=', 'brands.id')
    ->join('categories', 'products.category_id', '=', 'categories.id')
    ->select(['products.*', 'brands.name as brand_name', 'categories.name as category_name'])
    ->where('products.active', '=', 1)
    ->where('products.stock', '>', 0)
    ->whereBetween('products.price', 100, 1000)
    ->fullTextSearch(
        ['products.name', 'products.description', 'products.keywords'],
        'smartphone camera battery',
        [
            'boost_fields' => [
                'products.name' => 3.0,        // Nombre tiene más peso
                'products.keywords' => 2.0,    // Keywords importantes
                'products.description' => 1.0   // Descripción peso normal
            ],
            'boost_conditions' => [
                'discount > 0' => 1.5           // Productos en oferta
            ]
        ]
    )
    ->orderBy('products.rating', 'DESC')  // Orden secundario por rating
    ->limit(50);

// Búsqueda por categoría específica
$categorySearch = $orm->table('products')
    ->where('category_id', '=', $categoryId)
    ->fullTextSearch(['name', 'description'], $searchTerm);

// Búsqueda con autocompletado
$suggestions = $orm->table('products')
    ->select(['name'])
    ->fullTextSearch(['name'], $partialTerm)
    ->limit(10);
```

#### Búsqueda en Contenido Multiidioma

**❌ SQL tradicional:**
```sql
-- Manejo complejo de múltiples idiomas
SELECT *,
       CASE
           WHEN language = 'es' THEN MATCH(title, content) AGAINST('búsqueda avanzada' IN NATURAL LANGUAGE MODE)
           WHEN language = 'en' THEN MATCH(title, content) AGAINST('advanced search' IN NATURAL LANGUAGE MODE)
           ELSE MATCH(title, content) AGAINST('advanced search' IN NATURAL LANGUAGE MODE)
       END as relevance
FROM blog_posts
WHERE (
    (language = 'es' AND MATCH(title, content) AGAINST('búsqueda avanzada' IN NATURAL LANGUAGE MODE))
    OR
    (language = 'en' AND MATCH(title, content) AGAINST('advanced search' IN NATURAL LANGUAGE MODE))
)
ORDER BY relevance DESC;
```

**✅ VersaORM:**
```php
// Búsqueda multiidioma simplificada
$searchTerms = [
    'es' => 'búsqueda avanzada',
    'en' => 'advanced search',
    'fr' => 'recherche avancée'
];

$currentLanguage = 'es';
$fallbackLanguage = 'en';

$blogPosts = $orm->table('blog_posts')
    ->where('language', '=', $currentLanguage)
    ->fullTextSearch(
        ['title', 'content'],
        $searchTerms[$currentLanguage],
        ['language' => $currentLanguage]
    );

// Si no hay resultados, buscar en idioma alternativo
if (empty($blogPosts)) {
    $blogPosts = $orm->table('blog_posts')
        ->where('language', '=', $fallbackLanguage)
        ->fullTextSearch(
            ['title', 'content'],
            $searchTerms[$fallbackLanguage],
            ['language' => $fallbackLanguage]
        );
}

// Búsqueda combinada en múltiples idiomas
$multiLanguageSearch = $orm->table('blog_posts')
    ->whereIn('language', ['es', 'en'])
    ->fullTextSearch(['title', 'content'], 'technology', [
        'auto_language_detection' => true
    ]);
```

---

---

## ⚙️ Características Específicas del Motor

VersaORM se adapta automáticamente a las capacidades específicas de cada motor de base de datos, aprovechando al máximo sus características únicas.

### 🎯 ¿Para qué sirve conocer las capacidades?

- Optimizar consultas según el motor específico
- Validar funcionalidades antes de usarlas
- Adaptar la aplicación según limitaciones
- Monitorear rendimiento y recursos

### 🔧 Funciones Disponibles

- `getDriverCapabilities()`: Capacidades y características soportadas
- `getDriverLimits()`: Límites y restricciones del motor
- `optimizeQuery()`: Sugerencias de optimización automática

### 💡 Ejemplos Comparativos

#### Detectar Capacidades del Motor

**❌ Método tradicional:**
```php
// Código manual específico para cada motor
$pdo = new PDO($dsn, $user, $pass);
$version = $pdo->query("SELECT VERSION()")->fetchColumn();

if (strpos($version, 'MySQL') !== false) {
    $mysqlVersion = explode('.', $version);
    $supportsWindowFunctions = $mysqlVersion[0] >= 8;
    $supportsJSON = $mysqlVersion[0] >= 5 && $mysqlVersion[1] >= 7;
} elseif (strpos($version, 'PostgreSQL') !== false) {
    // Lógica específica para PostgreSQL
    $supportsWindowFunctions = true; // Desde versión 8.4
    $supportsJSON = true;
} else {
    // Más código para otros motores...
}
```

**✅ VersaORM:**
```php
// Detección automática y universal
$capabilities = $orm->table('users')->getDriverCapabilities();

// Ejemplo de resultado:
[
    'driver' => 'mysql',
    'version' => '8.0.33',
    'supports_window_functions' => true,
    'supports_cte' => true,
    'supports_recursive_cte' => true,
    'supports_json' => true,
    'supports_full_text_search' => true,
    'supports_percentile' => true,
    'max_connections' => 151,
    'charset' => 'utf8mb4'
]

// Usar las capacidades dinámicamente
if ($capabilities['supports_window_functions']) {
    $rankings = $orm->table('employees')
        ->windowFunction('rank', 'salary', [], ['department']);
} else {
    // Fallback para motores sin window functions
    $rankings = $orm->table('employees')
        ->orderBy('salary', 'DESC')
        ->get();
}
```

#### Conocer Límites del Motor

**❌ Método tradicional:**
```php
// Consultas específicas y manuales
$maxQueryLength = $pdo->query("SHOW VARIABLES LIKE 'max_allowed_packet'")->fetch();
$maxTableNameLength = 64; // Hardcoded para MySQL
$maxConnections = $pdo->query("SHOW VARIABLES LIKE 'max_connections'")->fetch();

// Diferentes queries para cada motor...
```

**✅ VersaORM:**
```php
// Límites normalizados automáticamente
$limits = $orm->table('users')->getDriverLimits();

// Ejemplo de resultado:
[
    'max_query_length' => 1048576,           // Tamaño máximo de consulta
    'max_table_name_length' => 64,          // Longitud máxima nombre de tabla
    'max_column_name_length' => 64,         // Longitud máxima nombre de columna
    'max_index_length' => 767,              // Longitud máxima de índice
    'max_connections' => 151,               // Conexiones simultáneas
    'max_join_tables' => 61,                // Tablas máximas en JOIN
    'max_group_by_columns' => 4096          // Columnas máximas en GROUP BY
]

// Validar antes de realizar operaciones
if (strlen($tableName) > $limits['max_table_name_length']) {
    throw new Exception("Nombre de tabla muy largo para este motor");
}

// Ajustar batch size según límites
$optimalBatchSize = min(1000, $limits['max_query_length'] / 100);
$orm->table('products')->insertMany($records, $optimalBatchSize);
```

#### Optimización Automática de Consultas

**❌ Análisis manual:**
```sql
-- Usar EXPLAIN manualmente para cada consulta
EXPLAIN FORMAT=JSON
SELECT u.*, p.bio
FROM users u
LEFT JOIN profiles p ON u.id = p.user_id
WHERE u.age > 25 AND u.city = 'Madrid'
ORDER BY u.created_at DESC;

-- Interpretar resultados y optimizar manualmente...
```

**✅ VersaORM:**
```php
// Análisis y sugerencias automáticas
$queryBuilder = $orm->table('users')
    ->select(['users.*', 'profiles.bio'])
    ->leftJoin('profiles', 'users.id', '=', 'profiles.user_id')
    ->where('users.age', '>', 25)
    ->where('users.city', '=', 'Madrid')
    ->orderBy('users.created_at', 'DESC');

$optimization = $queryBuilder->optimizeQuery();

// Ejemplo de resultado:
[
    'original_cost' => 1250,
    'optimized_cost' => 420,
    'improvement' => '66% faster',
    'suggested_indexes' => [
        'users_city_age_idx' => 'CREATE INDEX users_city_age_idx ON users(city, age)',
        'users_created_at_idx' => 'CREATE INDEX users_created_at_idx ON users(created_at DESC)'
    ],
    'query_plan' => [
        'type' => 'index_merge',
        'possible_keys' => ['city_idx', 'age_idx'],
        'rows_examined' => 150,
        'rows_returned' => 42
    ],
    'recommendations' => [
        'Consider reordering WHERE conditions by selectivity',
        'Add composite index on (city, age) for better performance',
        'Current query will benefit from covering index'
    ]
]

// Aplicar optimizaciones automáticamente
foreach ($optimization['suggested_indexes'] as $name => $sql) {
    echo "Ejecutar: $sql\n";
}
```

#### Ejemplo Real: Aplicación Multi-Motor

```php
// Aplicación que funciona con MySQL, PostgreSQL y SQLite
class DatabaseService
{
    private $orm;
    private $capabilities;
    private $limits;

    public function __construct($orm)
    {
        $this->orm = $orm;
        $this->capabilities = $orm->table('temp')->getDriverCapabilities();
        $this->limits = $orm->table('temp')->getDriverLimits();
    }

    public function getTopPerformers($department = null)
    {
        $query = $this->orm->table('employees');

        if ($department) {
            $query->where('department', '=', $department);
        }

        // Usar window functions si están disponibles
        if ($this->capabilities['supports_window_functions']) {
            return $query->windowFunction(
                'rank',
                'performance_score',
                [],
                ['department'],
                [['column' => 'performance_score', 'direction' => 'DESC']],
                'rank'
            );
        } else {
            // Fallback para motores sin window functions
            return $query->orderBy('performance_score', 'DESC')
                        ->limit(10)
                        ->get();
        }
    }

    public function bulkInsert($data)
    {
        // Ajustar batch size según límites del motor
        $maxBatchSize = min(
            1000,
            floor($this->limits['max_query_length'] / 200)  // Estimación conservadora
        );

        return $this->orm->table('bulk_data')
                         ->insertMany($data, $maxBatchSize);
    }

    public function complexSearch($term)
    {
        $query = $this->orm->table('articles');

        // Usar full-text search si está disponible
        if ($this->capabilities['supports_full_text_search']) {
            return $query->fullTextSearch(['title', 'content'], $term);
        } else {
            // Fallback con LIKE para motores básicos
            return $query->where('title', 'LIKE', "%$term%")
                        ->orWhere('content', 'LIKE', "%$term%")
                        ->get();
        }
    }
}

// Uso del servicio adaptativo
$service = new DatabaseService($orm);
$topPerformers = $service->getTopPerformers('Engineering');
$searchResults = $service->complexSearch('database optimization');
```

---

---

## 🔒 Validaciones de Seguridad

VersaORM incluye múltiples capas de seguridad integradas para prevenir inyección SQL y otros ataques, sin sacrificar funcionalidad.

### 🛡️ Capas de Protección

- **Validación de identificadores**: Nombres seguros de tablas, columnas y aliases
- **Sanitización de expresiones raw**: Detección de patrones SQL maliciosos
- **Límites operacionales**: Prevención de operaciones masivas destructivas
- **Parámetros seguros**: Binding automático de valores
- **Validación de sintaxis**: Verificación de estructura SQL

### 💡 Ejemplos de Seguridad

#### Protección contra Inyección SQL

**❌ Vulnerable (SQL tradicional):**
```php
// NUNCA hagas esto - vulnerable a inyección SQL
$userInput = $_POST['search']; // Podría ser: "'; DROP TABLE users; --"
$sql = "SELECT * FROM products WHERE name LIKE '%$userInput%'";
$result = $pdo->query($sql); // ¡PELIGROSO!
```

**✅ Protegido (VersaORM):**
```php
// VersaORM protege automáticamente
$userInput = $_POST['search']; // Aunque sea malicioso
$products = $orm->table('products')
    ->fullTextSearch(['name', 'description'], $userInput);

// O con filtros normales - también seguro
$products = $orm->table('products')
    ->where('name', 'LIKE', "%$userInput%"); // Parámetros automáticamente seguros

// ✅ Resultado: El input malicioso se trata como texto literal, no como código SQL
```

#### Validación de Identificadores

**❌ Peligroso:**
```php
// Intentar inyectar código en nombres de columna
try {
    $result = $orm->table('users')
        ->windowFunction('row_number', 'salary; DROP TABLE users;');
} catch (VersaORMException $e) {
    echo "🛡️ Identificador malicioso detectado y bloqueado";
}
```

**✅ Seguro:**
```php
// Identificadores válidos funcionan normalmente
$rankings = $orm->table('employees')
    ->windowFunction('row_number', 'salary');  // ✅ Válido

$rankings = $orm->table('employees')
    ->windowFunction('rank', 'performance_score');  // ✅ Válido
```

#### Protección en CTEs

**❌ Intento de ataque:**
```php
try {
    $ctes = [
        'malicious_cte' => [
            'query' => 'SELECT * FROM users; DROP TABLE passwords; --',
            'bindings' => []
        ]
    ];
    $result = $orm->table('users')->withCte($ctes, 'SELECT * FROM malicious_cte');
} catch (VersaORMException $e) {
    echo "🛡️ Expresión SQL maliciosa detectada y bloqueada";
}
```

**✅ Uso legítimo protegido:**
```php
// CTEs legítimos funcionan sin problemas
$ctes = [
    'high_performers' => [
        'query' => 'SELECT * FROM employees WHERE performance_score > ?',
        'bindings' => [8.5]  // Parámetros seguros
    ]
];

$result = $orm->table('employees')->withCte(
    $ctes,
    'SELECT department, COUNT(*) as count FROM high_performers GROUP BY department'
);
// ✅ Completamente seguro y funcional
```

#### Límites de Operación Seguros

```php
// Protección contra operaciones masivas accidentales
try {
    // Intentar eliminar sin condiciones WHERE
    $result = $orm->table('users')->deleteMany();
} catch (VersaORMException $e) {
    echo "🛡️ Operación DELETE sin WHERE bloqueada por seguridad";
}

// ✅ Operación segura con condiciones
$result = $orm->table('users')
    ->where('last_login', '<', date('Y-m-d', strtotime('-1 year')))
    ->deleteMany(100);  // Límite máximo por seguridad

// Protección contra batch sizes excesivos
try {
    $hugeArray = array_fill(0, 50000, ['name' => 'test']);
    $result = $orm->table('test')->insertMany($hugeArray);
} catch (VersaORMException $e) {
    echo "🛡️ Batch size excesivo detectado, usar batch_size menor";
}
```

---

## 💡 Ejemplos de Uso Completos

### Dashboard Ejecutivo de Ventas

```php
<?php
use VersaORM\VersaORM;

// Configuración segura automática
$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'sales_db',
    'username' => 'app_user',
    'password' => env('DB_PASSWORD')
]);

class SalesDashboard
{
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function getQuarterlyMetrics($year = 2024)
    {
        // 1. Ventas por trimestre con tendencias (Window Functions)
        $quarterlyTrends = $this->orm->table('sales')
            ->where('YEAR(sale_date)', '=', $year)
            ->windowFunction(
                'lag',
                'total_amount',
                ['offset' => 1, 'default_value' => 0],
                ['quarter'],
                [['column' => 'quarter', 'direction' => 'ASC']],
                'previous_quarter'
            );

        // 2. Análisis de percentiles de vendedores (Agregaciones Avanzadas)
        $topPerformers = $this->orm->table('sales')
            ->where('YEAR(sale_date)', '=', $year)
            ->advancedAggregation(
                'percentile',
                'commission',
                ['percentile' => 0.95],
                ['salesperson_id'],
                'top_5_percent_commission'
            );

        // 3. Productos más vendidos por región (CTE + Aggregations)
        $ctes = [
            'regional_sales' => [
                'query' => 'SELECT region, product_id, SUM(quantity) as total_qty
                           FROM sales s
                           JOIN customers c ON s.customer_id = c.id
                           WHERE YEAR(s.sale_date) = ?
                           GROUP BY region, product_id',
                'bindings' => [$year]
            ]
        ];

        $topProducts = $this->orm->table('sales')->withCte(
            $ctes,
            'SELECT rs.region, p.name as product_name, rs.total_qty,
                    RANK() OVER (PARTITION BY rs.region ORDER BY rs.total_qty DESC) as rank
             FROM regional_sales rs
             JOIN products p ON rs.product_id = p.id'
        );

        // 4. Búsqueda de productos con features específicas (JSON Operations)
        $premiumProducts = $this->orm->table('products')
            ->jsonOperation(
                'contains',
                'features',
                '$.categories',
                'premium'
            );

        // 5. Combinar datos históricos y actuales (UNION)
        $allSalesData = $this->orm->table('sales_2024')->union([
            [
                'sql' => 'SELECT sale_date, amount, "current" as period FROM sales_2024 WHERE amount > ?',
                'bindings' => [1000]
            ],
            [
                'sql' => 'SELECT sale_date, amount, "historical" as period FROM sales_archive WHERE amount > ?',
                'bindings' => [1000]
            ]
        ], true); // UNION ALL para mejor performance

        return [
            'quarterly_trends' => $quarterlyTrends,
            'top_performers' => $topPerformers,
            'top_products_by_region' => $topProducts,
            'premium_products' => $premiumProducts,
            'sales_comparison' => $allSalesData
        ];
    }

    public function searchIntelligent($searchTerm)
    {
        // Búsqueda inteligente multi-tabla
        return $this->orm->table('products')
            ->join('categories', 'products.category_id', '=', 'categories.id')
            ->fullTextSearch(
                ['products.name', 'products.description', 'categories.name'],
                $searchTerm,
                ['boost_title' => 2.0]
            );
    }
}

// Uso del dashboard
$dashboard = new SalesDashboard($orm);
$metrics = $dashboard->getQuarterlyMetrics(2024);
$searchResults = $dashboard->searchIntelligent('smartphone camera');

// Todo automáticamente seguro, optimizado y compatible entre motores
?>
```

---

## 🚀 Mejores Prácticas

### 1. **Performance**
- Usa `UNION ALL` cuando no necesites eliminar duplicados
- Prefiere window functions sobre subconsultas complejas
- Crea índices en columnas usadas en `PARTITION BY` y `ORDER BY`
- Para JSON, indexa rutas frecuentemente consultadas

### 2. **Seguridad**
- Siempre usa parámetros en lugar de concatenar strings
- Valida input del usuario antes de pasarlo a funciones avanzadas
- Usa condiciones WHERE en operaciones destructivas
- Limita el tamaño de batch operations

### 3. **Mantenibilidad**
- Divide consultas complejas en CTEs pequeños y legibles
- Usa aliases descriptivos para funciones de ventana
- Documenta lógica de negocio en CTEs recursivos
- Prefer métodos específicos (`median()`) sobre genéricos (`percentile(0.5)`)

### 4. **Compatibilidad**
- Verifica capacidades del motor antes de usar funciones avanzadas
- Implementa fallbacks para motores con soporte limitado
- Usa las funciones de VersaORM en lugar de SQL específico del motor

---

## 📋 Compatibilidad por Motor

| Función | MySQL 8.0+ | PostgreSQL 12+ | SQLite 3.25+ | Notas |
|---------|-------------|----------------|--------------|--------|
| Window Functions | ✅ Completo | ✅ Completo | ⚠️ Limitado | SQLite: Sin RANGE/ROWS |
| CTEs | ✅ Completo | ✅ Completo | ✅ Completo | Soporte universal |
| CTEs Recursivos | ✅ Completo | ✅ Completo | ✅ Completo | Límite de profundidad |
| JSON Operations | ✅ Nativo | ✅ JSONB | ⚠️ Limitado | SQLite: Sin índices JSON |
| Full-text Search | ✅ FULLTEXT | ✅ tsvector | ⚠️ FTS5 | Configuración específica |
| Percentiles | ✅ Nativo | ✅ Nativo | ⚠️ Emulado | VersaORM normaliza |
| UNION Operations | ✅ Completo | ✅ Completo | ✅ Completo | Soporte universal |

**Leyenda**: ✅ Soporte completo, ⚠️ Soporte limitado o emulado

---

¡Felicidades! Ahora dominas las funcionalidades SQL más avanzadas de VersaORM. Para más información consulta la [documentación principal](../README.md) o explora otras guías específicas.

🎯 **Próximos pasos recomendados:**
- [⚡ Modo Lazy y Planificador de Consultas](10-lazy-mode-query-planner.md)
- [🔄 Operaciones UPSERT y REPLACE INTO](11-upsert-replace-operations.md)
- [⚙️ Query Builder - Ejemplos Rápidos](12-query-builder-quick-examples.md)
        ]
    ];
    $qb->withCte($ctes, 'SELECT * FROM unsafe_cte');
} catch (VersaORMException $e) {
    echo "Expresión SQL maliciosa detectada";
}
```

---

## 💡 Ejemplos de Uso Completos

### Dashboard Ejecutivo de Ventas

```php
<?php
use VersaORM\VersaORM;

// Configuración segura automática
$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'sales_db',
    'username' => 'app_user',
    'password' => env('DB_PASSWORD')
]);

class SalesDashboard
{
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function getQuarterlyMetrics($year = 2024)
    {
        // 1. Ventas por trimestre con tendencias (Window Functions)
        $quarterlyTrends = $this->orm->table('sales')
            ->where('YEAR(sale_date)', '=', $year)
            ->windowFunction(
                'lag',
                'total_amount',
                ['offset' => 1, 'default_value' => 0],
                ['quarter'],
                [['column' => 'quarter', 'direction' => 'ASC']],
                'previous_quarter'
            );

        // 2. Análisis de percentiles de vendedores (Agregaciones Avanzadas)
        $topPerformers = $this->orm->table('sales')
            ->where('YEAR(sale_date)', '=', $year)
            ->advancedAggregation(
                'percentile',
                'commission',
                ['percentile' => 0.95],
                ['salesperson_id'],
                'top_5_percent_commission'
            );

        // 3. Productos más vendidos por región (CTE + Aggregations)
        $ctes = [
            'regional_sales' => [
                'query' => 'SELECT region, product_id, SUM(quantity) as total_qty
                           FROM sales s
                           JOIN customers c ON s.customer_id = c.id
                           WHERE YEAR(s.sale_date) = ?
                           GROUP BY region, product_id',
                'bindings' => [$year]
            ]
        ];

        $topProducts = $this->orm->table('sales')->withCte(
            $ctes,
            'SELECT rs.region, p.name as product_name, rs.total_qty,
                    RANK() OVER (PARTITION BY rs.region ORDER BY rs.total_qty DESC) as rank
             FROM regional_sales rs
             JOIN products p ON rs.product_id = p.id'
        );

        // 4. Búsqueda de productos con features específicas (JSON Operations)
        $premiumProducts = $this->orm->table('products')
            ->jsonOperation(
                'contains',
                'features',
                '$.categories',
                'premium'
            );

        // 5. Combinar datos históricos y actuales (UNION)
        $allSalesData = $this->orm->table('sales_2024')->union([
            [
                'sql' => 'SELECT sale_date, amount, "current" as period FROM sales_2024 WHERE amount > ?',
                'bindings' => [1000]
            ],
            [
                'sql' => 'SELECT sale_date, amount, "historical" as period FROM sales_archive WHERE amount > ?',
                'bindings' => [1000]
            ]
        ], true); // UNION ALL para mejor performance

        return [
            'quarterly_trends' => $quarterlyTrends,
            'top_performers' => $topPerformers,
            'top_products_by_region' => $topProducts,
            'premium_products' => $premiumProducts,
            'sales_comparison' => $allSalesData
        ];
    }

    public function searchIntelligent($searchTerm)
    {
        // Búsqueda inteligente multi-tabla
        return $this->orm->table('products')
            ->join('categories', 'products.category_id', '=', 'categories.id')
            ->fullTextSearch(
                ['products.name', 'products.description', 'categories.name'],
                $searchTerm,
                ['boost_title' => 2.0]
            );
    }
}

// Uso del dashboard
$dashboard = new SalesDashboard($orm);
$metrics = $dashboard->getQuarterlyMetrics(2024);
$searchResults = $dashboard->searchIntelligent('smartphone camera');

// Todo automáticamente seguro, optimizado y compatible entre motores
?>
```

---

## 🚀 Mejores Prácticas

### 1. **Performance**
- Usa `UNION ALL` cuando no necesites eliminar duplicados
- Prefiere window functions sobre subconsultas complejas
- Crea índices en columnas usadas en `PARTITION BY` y `ORDER BY`
- Para JSON, indexa rutas frecuentemente consultadas

### 2. **Seguridad**
- Siempre usa parámetros en lugar de concatenar strings
- Valida input del usuario antes de pasarlo a funciones avanzadas
- Usa condiciones WHERE en operaciones destructivas
- Limita el tamaño de batch operations

### 3. **Mantenibilidad**
- Divide consultas complejas en CTEs pequeños y legibles
- Usa aliases descriptivos para funciones de ventana
- Documenta lógica de negocio en CTEs recursivos
- Prefer métodos específicos (`median()`) sobre genéricos (`percentile(0.5)`)

### 4. **Compatibilidad**
- Verifica capacidades del motor antes de usar funciones avanzadas
- Implementa fallbacks para motores con soporte limitado
- Usa las funciones de VersaORM en lugar de SQL específico del motor

---

## 📋 Compatibilidad por Motor

| Función | MySQL 8.0+ | PostgreSQL 12+ | SQLite 3.25+ | Notas |
|---------|-------------|----------------|--------------|--------|
| Window Functions | ✅ Completo | ✅ Completo | ⚠️ Limitado | SQLite: Sin RANGE/ROWS |
| CTEs | ✅ Completo | ✅ Completo | ✅ Completo | Soporte universal |
| CTEs Recursivos | ✅ Completo | ✅ Completo | ✅ Completo | Límite de profundidad |
| JSON Operations | ✅ Nativo | ✅ JSONB | ⚠️ Limitado | SQLite: Sin índices JSON |
| Full-text Search | ✅ FULLTEXT | ✅ tsvector | ⚠️ FTS5 | Configuración específica |
| Percentiles | ✅ Nativo | ✅ Nativo | ⚠️ Emulado | VersaORM normaliza |
| UNION Operations | ✅ Completo | ✅ Completo | ✅ Completo | Soporte universal |

**Leyenda**: ✅ Soporte completo, ⚠️ Soporte limitado o emulado

---

¡Felicidades! Ahora dominas las funcionalidades SQL más avanzadas de VersaORM. Para más información consulta la [documentación principal](../README.md) o explora otras guías específicas.

🎯 **Próximos pasos recomendados:**
- [⚡ Modo Lazy y Planificador de Consultas](10-lazy-mode-query-planner.md)
- [🔄 Operaciones UPSERT y REPLACE INTO](11-upsert-replace-operations.md)
- [⚙️ Query Builder - Ejemplos Rápidos](12-query-builder-quick-examples.md)
