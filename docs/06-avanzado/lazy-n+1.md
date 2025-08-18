# Lazy Loading y Detección de N+1

Optimiza acceso a relaciones evitando tormentas de queries redundantes.

## ✅ Prerrequisitos
- Haber leído [CRUD Básico](../03-basico/crud-basico.md)
- Conocer creación de relaciones en tus modelos (métodos `algoArray()`)
- Familiaridad con [Operaciones Batch](operaciones-batch.md) para optimizar consultas derivadas

> Si vienes de CRUD Básico: este capítulo te muestra por qué llamar relaciones dentro de un bucle puede multiplicar queries y cómo reducirlo a pocas consultas agregadas.

## N+1: Qué es
Patrón donde cargas una lista (N filas) y luego para cada fila disparas otra consulta por una relación, generando N+1 queries totales.

```php
$users = $orm->table('users')->limit(50)->get();
foreach ($users as $u) {
    $posts = $u->postsArray(); // ❌ Si cada llamada hace una query
}
```
**SQL resultante ineficiente (esquema simplificado):**
```sql
SELECT * FROM users LIMIT 50; -- 1 query
SELECT * FROM posts WHERE user_id = 1; -- repetido hasta N
...
```

## Estrategias de Mitigación
| Estrategia | Uso | Beneficio |
|-----------|-----|-----------|
| Pre-carga manual | Cargar IDs y luego un IN masivo | Reduce a 2 queries |
| Agrupación diferida | Acumular IDs y resolver al final | Minimiza repeticiones |
| Cache por ciclo | Memorizar resultado de una relación ya resuelta | Evita consultas duplicadas |

## Pre-carga Manual (Pattern)
Supongamos relación 1:N usuarios→posts:
```php
$users = $orm->table('users')->limit(50)->get();
$userIds = array_column($users, 'id');
$posts = $orm->table('posts')->whereIn('user_id', $userIds)->get();
// Indexar por user_id
$byUser = [];
foreach ($posts as $p) { $byUser[$p['user_id']][] = $p; }
// Asignar
foreach ($users as &$u) { $u['posts'] = $byUser[$u['id']] ?? []; }
```
**SQL Equivalente optimizado:**
```sql
SELECT * FROM users LIMIT 50;
SELECT * FROM posts WHERE user_id IN (/* lista de 50 ids */);
```

## Lazy Seguro con Cache en Memoria
```php
class UserModel extends VersaModel {
  private static array $relCache = [];
  public function postsArray(): array {
    $id = $this->id;
    if (!$id) return [];
    if (!isset(self::$relCache['posts'][$id])) {
      self::$relCache['posts'][$id] = self::getORM()
        ->table('posts')->where('user_id','=',$id)->get();
    }
    return self::$relCache['posts'][$id];
  }
}
```
**SQL (primer acceso a cada user_id):**
```sql
SELECT * FROM posts WHERE user_id = ?;
```
Luego cachea en memoria y no repite query dentro del ciclo.
Resetea la cache estática entre peticiones web si corresponde.

## Detección con Métricas
1. Lee queries iniciales.
2. Ejecuta bloque sospechoso.
3. Vuelve a leer métricas.
4. Si la diferencia ≈ N elementos, hay N+1.
```php
$before = $orm->metrics()['queries'];
// Bloque
$after = $orm->metrics()['queries'];
if (($after - $before) > 20) { error_log('Posible N+1 detectado'); }
```

## Relaciones Muchos a Muchos
Patrón similar con tabla pivote:
```php
$tasks = $orm->table('tasks')->limit(30)->get();
$taskIds = array_column($tasks,'id');
$links = $orm->table('task_labels')->whereIn('task_id',$taskIds)->get();
$labelIds = array_unique(array_column($links,'label_id'));
$labels = $orm->table('labels')->whereIn('id',$labelIds)->get();
// Indexar
$labelsById = []; foreach ($labels as $l) { $labelsById[$l['id']] = $l; }
$labelsByTask = [];
foreach ($links as $lnk) { $labelsByTask[$lnk['task_id']][] = $labelsById[$lnk['label_id']]; }
foreach ($tasks as &$t) { $t['labels'] = $labelsByTask[$t['id']] ?? []; }
```
**SQL Equivalente optimizado:**
```sql
SELECT * FROM tasks LIMIT 30;
SELECT * FROM task_labels WHERE task_id IN (/* 30 ids */);
SELECT * FROM labels WHERE id IN (/* ids de etiquetas únicas */);
```

## Checklist Anti N+1
- [ ] Evitas llamar relaciones dentro de loops sin cache
- [ ] Agrupas IDs y haces `WHERE IN` masivo
- [ ] Cacheas relaciones ya resueltas en memoria ciclo
- [ ] Monitoreas métricas `queries`
- [ ] Refactorizas cuando la diferencia de queries crece lineal con N

## ➡️ Próximos Pasos
- Profundiza en [Caché Interna](cache-interna.md) para reducir lecturas repetidas.
- Revisa [Métricas y Observabilidad](observabilidad/metricas.md) para cuantificar mejoras.
- Continúa con [Arquitectura y Flujo Interno](arquitectura-flujo-interno.md) si quieres entender el pipeline.
