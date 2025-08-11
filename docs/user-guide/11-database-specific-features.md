# ⚠️ Nota Modo PHP / PDO
Las diferencias específicas por motor se gestionan actualmente vía PDO estándar. Optimización futura nativa no requerirá cambios de API.

# Funcionalidades SQL Avanzadas por Motor de Base de Datos

## MySQL - Características Específicas

### Window Functions
MySQL 8.0+ soporta todas las funciones window estándar:

```php
$qb = new QueryBuilder($orm, 'sales');

// ROW_NUMBER con partición
$result = $qb->windowFunction(
    'row_number',
    '*',
    [],
    ['region', 'year'],
    [['column' => 'amount', 'direction' => 'DESC']],
    'row_num'
);

// LAG para comparaciones temporales
$result = $qb->windowFunction(
    'lag',
    'amount',
    ['offset' => 1, 'default_value' => 0],
    ['region'],
    [['column' => 'date', 'direction' => 'ASC']],
    'prev_amount'
);
```

### JSON Operations
MySQL usa sintaxis con `->` y `->>`:

```php
$qb = new QueryBuilder($orm, 'users');

// Extraer campo JSON
$result = $qb->jsonOperation('extract', 'profile', '$.name');

// Buscar en array JSON
$result = $qb->jsonOperation('contains', 'profile', '{"skills": ["PHP"]}');

// Longitud de array JSON
$result = $qb->jsonOperation('array_length', 'profile', '$.skills');
```

### Full-Text Search
MySQL requiere índices FULLTEXT:

```php
// Crear tabla con índice FULLTEXT
$orm->exec("
    CREATE TABLE articles (
        id INT PRIMARY KEY,
        title VARCHAR(255),
        content TEXT,
        FULLTEXT(title, content)
    )
");

$qb = new QueryBuilder($orm, 'articles');

// Búsqueda natural
$result = $qb->fullTextSearch(['title', 'content'], 'PHP programming', [
    'mode' => 'NATURAL LANGUAGE',
    'with_score' => true
]);

// Búsqueda booleana
$result = $qb->fullTextSearch(['title', 'content'], '+PHP -JavaScript', [
    'mode' => 'BOOLEAN'
]);
```

### Query Hints Específicos
MySQL soporta varios hints de optimización:

```php
$qb = new QueryBuilder($orm, 'orders');

$qb->queryHints([
    'USE_INDEX' => 'idx_customer_date',
    'SQL_CALC_FOUND_ROWS' => true,
    'SQL_NO_CACHE' => true
]);
```

### Advanced Aggregations
GROUP_CONCAT es específico de MySQL:

```php
$qb = new QueryBuilder($orm, 'employees');

// GROUP_CONCAT con separador personalizado
$result = $qb->advancedAggregation('group_concat', 'name', [
    'separator' => ' | ',
    'order_by' => 'hire_date DESC',
    'distinct' => true
]);
```

## PostgreSQL - Características Específicas

### Array Operations
PostgreSQL tiene soporte nativo para arrays:

```php
$qb = new QueryBuilder($orm, 'products');

// Verificar si array contiene elemento
$result = $qb->arrayOperations('contains', 'tags', 'electronics');

// Verificar overlap entre arrays
$result = $qb->arrayOperations('overlap', 'tags', ['electronics', 'mobile']);

// Obtener longitud de array
$result = $qb->arrayOperations('length', 'tags');

// Agregar elemento al array
$result = $qb->arrayOperations('append', 'tags', 'new_tag');
```

### JSONB Operations
PostgreSQL usa JSONB para mejor performance:

```php
$qb = new QueryBuilder($orm, 'users');

// Operaciones con JSONB
$result = $qb->jsonOperation('contains', 'profile', '{"level": "senior"}');

// Extraer claves de JSONB
$result = $qb->jsonOperation('keys', 'profile');

// Buscar en JSONB con path queries
$result = $qb->jsonOperation('extract', 'profile', '$.certifications[*].name');
```

### Full-Text Search con tsvector
PostgreSQL usa tsvector y tsquery:

```php
$qb = new QueryBuilder($orm, 'documents');

// Búsqueda con ranking
$result = $qb->fullTextSearch(['search_vector'], 'database optimization', [
    'language' => 'english',
    'operator' => '@@',
    'rank' => true,
    'headline' => true
]);
```

### CTEs Recursivos Avanzados
PostgreSQL tiene excelente soporte para CTEs recursivos:

```php
$qb = new QueryBuilder($orm, 'employees');

// Jerarquía organizacional
$result = $qb->withCte([
    'org_hierarchy' => [
        'query' => 'WITH RECURSIVE hierarchy AS (
            SELECT id, name, manager_id, 1 as level, ARRAY[id] as path
            FROM employees WHERE manager_id IS NULL
            UNION ALL
            SELECT e.id, e.name, e.manager_id, h.level + 1, h.path || e.id
            FROM employees e
            JOIN hierarchy h ON e.manager_id = h.id
            WHERE NOT (e.id = ANY(h.path))
        ) SELECT * FROM hierarchy',
        'bindings' => []
    ]
], 'SELECT * FROM org_hierarchy ORDER BY level, name', []);
```

### Estadísticas Avanzadas
PostgreSQL tiene funciones estadísticas robustas:

```php
$qb = new QueryBuilder($orm, 'sales');

// Percentiles continuos
$result = $qb->advancedAggregation('percentile', 'amount', [
    'percentile' => 0.95,
    'method' => 'cont'
]);

// Variance y standard deviation
$result = $qb->advancedAggregation('variance', 'amount');
$result = $qb->advancedAggregation('stddev', 'amount');
```

## SQLite - Características Específicas

### Window Functions (SQLite 3.25+)
SQLite soporta window functions desde la versión 3.25:

```php
$qb = new QueryBuilder($orm, 'scores');

// Ranking dentro de grupos
$result = $qb->windowFunction(
    'rank',
    'score',
    [],
    ['category'],
    [['column' => 'score', 'direction' => 'DESC']],
    'score_rank'
);
```

### JSON Operations
SQLite usa json_extract y funciones JSON:

```php
$qb = new QueryBuilder($orm, 'settings');

// Extraer valores JSON
$result = $qb->jsonOperation('extract', 'config', '$.theme.color');

// Verificar tipo JSON
$result = $qb->jsonOperation('type', 'config', '$.timeout');
```

### Full-Text Search con FTS5
SQLite usa extensiones FTS para búsqueda:

```php
// Crear tabla virtual FTS5
$orm->exec("
    CREATE VIRTUAL TABLE docs_fts USING fts5(
        title, content,
        content='documents',
        content_rowid='id'
    )
");

$qb = new QueryBuilder($orm, 'docs_fts');

// Búsqueda con FTS5
$result = $qb->fullTextSearch(['title', 'content'], 'programming tutorial', [
    'fts_version' => 'fts5',
    'match_operator' => 'MATCH',
    'highlight' => true,
    'snippet' => true
]);
```

### CTEs Simples y Recursivos
SQLite soporta CTEs desde la versión 3.8.3:

```php
$qb = new QueryBuilder($orm, 'employees');

// Serie numérica recursiva
$result = $qb->withCte([
    'number_series' => [
        'query' => 'WITH RECURSIVE series(x) AS (
            SELECT 1
            UNION ALL
            SELECT x + 1 FROM series WHERE x < 100
        ) SELECT * FROM series',
        'bindings' => []
    ]
], 'SELECT x as number FROM number_series WHERE x % 10 = 0', []);
```

### Optimización de Consultas
SQLite tiene herramientas específicas de análisis:

```php
$qb = new QueryBuilder($orm, 'large_table');

// Obtener plan de ejecución
$result = $qb->optimizeQuery([
    'explain_query_plan' => true,
    'analyze_table' => true,
    'suggest_indexes' => true
]);
```

## Comparación de Características

| Característica | MySQL | PostgreSQL | SQLite |
|---------------|-------|------------|---------|
| Window Functions | ✅ 8.0+ | ✅ Completo | ✅ 3.25+ |
| JSON Operations | ✅ JSON | ✅ JSONB | ✅ Básico |
| Array Types | ❌ | ✅ Nativo | ❌ |
| Full-Text Search | ✅ FULLTEXT | ✅ tsvector | ✅ FTS5 |
| Recursive CTEs | ✅ 8.0+ | ✅ Completo | ✅ 3.8.3+ |
| Advanced Stats | ⚠️ Básico | ✅ Completo | ⚠️ Básico |
| Query Hints | ✅ Extenso | ✅ Config | ⚠️ Limitado |

## Ejemplos de Uso Multiplataforma

### Código que Funciona en Todos los Motores

```php
// Window function básica
$result = $qb->windowFunction('row_number', '*', [], ['department'],
    [['column' => 'salary', 'direction' => 'DESC']], 'row_num');

// JSON extraction básica
$result = $qb->jsonOperation('extract', 'profile', '$.name');

// CTE simple
$result = $qb->withCte([
    'summary' => [
        'query' => 'SELECT department, AVG(salary) as avg_sal FROM employees GROUP BY department',
        'bindings' => []
    ]
], 'SELECT * FROM summary WHERE avg_sal > 70000', []);

// Union operation
$result = $qb->union([
    ['sql' => 'SELECT name FROM employees WHERE department = ?', 'bindings' => ['IT']],
    ['sql' => 'SELECT name FROM employees WHERE department = ?', 'bindings' => ['HR']]
]);
```

### Detección Automática del Motor

```php
// Verificar capacidades antes de usar características específicas
$capabilities = $qb->getDriverCapabilities();

if ($capabilities['features']['array_support']) {
    // Usar array operations (PostgreSQL)
    $result = $qb->arrayOperations('contains', 'tags', 'php');
} else {
    // Usar alternativa compatible
    $result = $qb->where('tags', 'LIKE', '%php%')->get();
}
```

## Mejores Prácticas

1. **Portabilidad**: Usar características comunes cuando sea posible
2. **Performance**: Aprovechar características específicas del motor para casos críticos
3. **Testing**: Probar en todos los motores soportados
4. **Fallbacks**: Implementar alternativas para características no soportadas
5. **Configuración**: Usar detección automática de capacidades
