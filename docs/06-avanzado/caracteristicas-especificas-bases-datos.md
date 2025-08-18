# Características Específicas por Base de Datos

Resumen de capacidades avanzadas multi-driver y cómo usarlas de forma portable.

## Tabla Comparativa
| Feature | MySQL | PostgreSQL | SQLite | Notas |
|---------|-------|------------|--------|-------|
| JSON nativo | ✅ (JSON / JSON_TABLE parcial) | ✅ (JSONB potente) | ✅ (texto + funciones) | Usa `whereJsonContains` (roadmap) |
| Window Functions | ✅ (8.0+) | ✅ | ✅ (3.25+) | Preferir alias claros |
| CTE (WITH) | ✅ (8.0+) | ✅ | ✅ (3.8.3+) | Anidamiento soportado |
| Full Text | ✅ (MATCH AGAINST) | ✅ (to_tsvector) | ⚠️ (FTS5 opcional) | Normaliza idioma |
| Arrays | ❌ | ✅ | ⚠️ (simular) | Serializa a JSON cross-driver |
| UPSERT | ✅ | ✅ | ✅ | Implementado en `upsertMany` |
| RETURNING | ⚠️ (LIMITADO 8.0.21+) | ✅ | ⚠️ (3.35+) | Roadmap inserción precisa IDs |
| JSON Path | ✅ | ✅ | ⚠️ | Variaciones de sintaxis |
| Lateral Join | ❌ | ✅ | ⚠️ | Re-escribir como subquery si falta |

## JSON
```php
// Lectura filtrando campo JSON
$users = $orm->table('users')
  ->whereRaw("JSON_EXTRACT(meta, '$.active') = 1") // MySQL / SQLite
  ->get();
```
Portabilidad: encapsula condiciones JSON en métodos helper.

## Window Functions
```php
$rows = $orm->raw("SELECT id, name, ROW_NUMBER() OVER (PARTITION BY role ORDER BY created_at) rn FROM users");
```
Usos: ranking, paginación estable, agregaciones cumulativas.

## CTEs
```php
$sql = <<<SQL
WITH recent AS (
  SELECT id, created_at FROM users ORDER BY created_at DESC LIMIT 100
)
SELECT * FROM recent ORDER BY created_at;
SQL;
$data = $orm->raw($sql);
```

## Full Text
MySQL:
```php
$orm->raw("SELECT id FROM articles WHERE MATCH(title,body) AGAINST (? IN NATURAL LANGUAGE MODE)", ['php orm']);
```
PostgreSQL:
```php
$orm->raw("SELECT id FROM articles WHERE to_tsvector('simple', title || ' ' || body) @@ plainto_tsquery(?)", ['php orm']);
```

## Arrays (PostgreSQL)
```php
$orm->raw('SELECT * FROM posts WHERE tags && ARRAY[?,?]', ['php','orm']);
```
Estrategia cross-driver: usar JSON arrays y operadores que existan en todos.

## UPSERT Portátil
Usa `upsertMany` y deja que el motor genere la sintaxis correcta.

## Limitaciones y Adaptación
- Emplea `whereRaw` para brechas temporales hasta que existan helpers dedicados.
- Envuelve SQL específico en métodos de repositorio para aislar la lógica.

## Roadmap
- Helpers de JSON portables (`whereJsonContains`, `selectJsonPath`).
- Generador de CTEs fluido.
- Detección automática de capacidades (feature flags por driver).
