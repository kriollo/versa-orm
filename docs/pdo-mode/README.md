# 🧪 Modo PHP / PDO (Sin Núcleo Nativo)

Esta guía concentra el uso de VersaORM únicamente con **PHP + PDO**, omitiendo el binario nativo mientras se estabiliza. Todo lo que ves aquí funciona hoy mismo con instalar vía Composer.

## ✅ Objetivos del Modo PDO
- Cero compilación ni dependencias nativas
- API estable para CRUD, filtros, joins y agregaciones
- Seguridad por defecto con prepared statements
- Transición futura transparente al núcleo nativo (sin reescribir código)

---
## 1. Instalación Rápida
```bash
composer require versaorm/versaorm-php
```
```php
require 'vendor/autoload.php';
use VersaORM\VersaORM;use VersaORM\VersaModel;
$orm = new VersaORM([
  'driver'=>'sqlite','database'=>__DIR__.'/app.sqlite'
]);
VersaModel::setORM($orm);
```

---
## 2. CRUD Esencial (Comparativo)
| Operación | SQL (PDO) | VersaORM |
|-----------|----------|----------|
| Insert | `$pdo->prepare("INSERT ...")` | `$u=VersaModel::dispense('users'); $u->name='Ana'; $u->store();` |
| Select 1 | `SELECT * FROM users WHERE id=?` | `$u=VersaModel::load('users',1);` |
| Update | `UPDATE users SET ...` | `$u->email='x@x.com'; $u->store();` |
| Delete | `DELETE FROM users WHERE id=?` | `$u->trash();` |

---
## 3. Query Builder Básico
```php
$activos = $orm->table('users')
  ->where('status','=','active')
  ->where('age','>=',18)
  ->orderBy('created_at','desc')
  ->limit(20)
  ->getAll();
```
Where encadenables, order, limit. Todos los valores se enlazan de forma segura.

### Operadores soportados
`=`, `!=`, `>`, `>=`, `<`, `<=`, `LIKE`, `IN`, `NOT IN`, `BETWEEN`, `IS NULL`, `IS NOT NULL`.

---
## 4. Joins (Guía Completa y Didáctica)
Los JOINs permiten combinar filas de varias tablas. VersaORM busca que el uso sea **explícito y simple** incluso para quien recién empieza.

### 4.1. Inner Join básico
```php
$rows = $orm->table('posts')
  ->select(['posts.id','posts.title','users.name AS author'])
  ->join('users','users.id','=','posts.user_id') // INNER JOIN
  ->getAll();
```
Equivalente SQL:
```sql
SELECT posts.id, posts.title, users.name AS author
FROM posts
INNER JOIN users ON users.id = posts.user_id;
```

### 4.2. Con alias (buena práctica en consultas largas)
```php
$rows = $orm->table('posts AS p')
  ->select(['p.id','p.title','u.name AS author'])
  ->join('users AS u','u.id','=','p.user_id')
  ->getAll();
```

### 4.3. Joins compuestos (varias condiciones ON)
Ahora puedes construir JOINs con múltiples comparaciones usando el patrón encadenado `->join()->on()->on()`.
```php
$rows = $orm->table('orders AS o')
  ->join('invoices AS i')                 // Declaras la tabla a unir
  ->on('o.id','=','i.order_id')           // Primera condición
  ->on('o.company_id','=','i.company_id') // Segunda condición (AND por defecto)
  ->getAll();
```
SQL resultante:
```sql
SELECT * FROM orders AS o
INNER JOIN invoices AS i
  ON o.id = i.order_id AND o.company_id = i.company_id;
```

#### 4.3.1. Usando OR entre condiciones
```php
$rows = $orm->table('sessions AS s')
  ->join('users AS u')
  ->on('s.user_id','=','u.id')
  ->on('s.admin_id','=','u.id','OR') // Mezcla lógica
  ->getAll();
```

### 4.4. Left / Right Join (diferencia clave)
```php
// LEFT JOIN: conserva filas de la izquierda aunque no haya coincidencia
$rows = $orm->table('users AS u')
  ->leftJoin('profiles AS p','u.id','=','p.user_id')
  ->getAll();
```
IMPORTANTE: Si filtras columnas de la tabla derecha en el **WHERE**, puedes convertir el LEFT en un INNER sin querer. Para mantener filas sin perfil, filtra con `whereNull('p.id')` o mueve condiciones adicionales al `ON` usando `->on()`.

### 4.5. Right Join
Si tu base lo soporta:
```php
$rows = $orm->table('profiles AS p')
  ->rightJoin('users AS u','u.id','=','p.user_id')
  ->getAll();
```

### 4.6. Full Outer Join (Emulado)
Cuando llamas a `fullOuterJoin()` VersaORM emula la operación (UNION de LEFT + RIGHT) en modo PDO. Úsalo sólo si realmente necesitas todos los registros de ambas tablas sin perder no coincidencias.
```php
$rows = $orm->table('users AS u')
  ->fullOuterJoin('posts AS p','u.id','=','p.user_id')
  ->getAll();
```
Limitaciones: No mezclar con más JOINs complejos (se recomienda una segunda consulta si necesitas lógica adicional).

### 4.7. Cross Join (Producto cartesiano)
```php
$pairs = $orm->table('currencies')
  ->crossJoin('countries')
  ->limit(100)
  ->getAll();
```

### 4.8. Join con Subconsulta
```php
$sub = $orm->table('posts')
  ->select(['user_id','COUNT(*) AS total_posts'])
  ->groupBy('user_id')
  ->having('total_posts','>',1);

$rows = $orm->table('users AS u')
  ->select(['u.name','t.total_posts'])
  ->joinSub($sub,'t','u.id','=','t.user_id')
  ->getAll();
```

### 4.9. Patrón completo join()->on()->on() con mezcla AND/OR
```php
$rows = $orm->table('documents AS d')
  ->join('revisions AS r')
  ->on('d.id','=','r.document_id')
  ->on('d.language','=','r.language')
  ->on('r.is_last','=',1,'AND')
  ->getAll();
```

### 4.10. ¿Cuándo usar ON vs WHERE?
| Quiero | Usa |
|--------|-----|
| Restringir cómo se emparejan las filas | `on()` |
| Filtrar filas finales después del JOIN | `where()` |
| Mantener filas sin coincidencia (LEFT) | Condiciones extra en `on()` |
| Forzar sólo coincidencias | `where()` sobre la tabla derecha |

### 4.11. Errores comunes
| Error | Causa | Solución |
|-------|-------|----------|
| LEFT actúa como INNER | Pusiste condición de la tabla derecha en WHERE | Mover a `on()` o usar `whereNull()` para conservar vacíos |
| Ambiguous column | Falta de alias/ prefijo | Pre-fija con `u.id`, `p.id` |
| JOIN sin columnas | Olvidaste encadenar `on()` | Añade al menos una `on()` después de `join()` |

### 4.12. Resumen rápido
```php
// Minimal
$qb->join('t2','t2.id','=','t1.ref_id');
// Compuesto
$qb->join('t2')->on('t2.id','=','t1.ref_id')->on('t2.type','=','t1.type');
// Con OR
$qb->join('t2')->on('t2.id','=','t1.ref_id')->on('t2.alt_id','=','t1.ref_id','OR');
```

Consejo: empieza simple; añade condiciones sólo cuando realmente describan la integridad entre las tablas.

---
## 5. Agregaciones
```php
$stats = $orm->table('orders')
  ->select(['customer_id','COUNT(*) total','SUM(amount) total_amount'])
  ->where('status','=','paid')
  ->groupBy('customer_id')
  ->having('total','>',3)
  ->getAll();
```

---
## 6. Paginación Sencilla
```php
$page = 2; $per=10;
$items = $orm->table('products')
  ->orderBy('id','desc')
  ->limit($per)->offset(($page-1)*$per)
  ->getAll();
```

---
## 7. Modelo Personalizado
```php
class User extends VersaModel {
  protected string $table='users';
  protected array $fillable=['name','email','status'];
  protected array $rules=[ 'email'=>['required','email'] ];
  public function posts(){
    return $this->orm()->table('posts')->where('user_id','=',$this->id)->getAll();
  }
}
User::setORM($orm);
$u = User::create(['name'=>'Ana','email'=>'ana@ex.com','status'=>'active']);
```

---
## 8. Transacciones
```php
$orm->transaction(function($orm){
  $o = VersaModel::dispense('orders');
  $o->amount = 120; $o->store();
  $p = VersaModel::dispense('payments');
  $p->order_id=$o->id; $p->status='captured'; $p->store();
});
```
Si una excepción ocurre dentro del closure se hace rollback automáticamente.

---
## 9. Actualizaciones / Borrados Masivos
```php
$orm->table('sessions')->where('last_seen','<',date('Y-m-d H:i:s',strtotime('-30 days')))->delete();
$orm->table('users')->where('status','=','pending')->update(['status'=>'inactive']);
```

---
## 10. Búsquedas Dinámicas (Filtros Opcionales)
```php
$q = $orm->table('products');
if(!empty($_GET['q'])) $q->where('name','LIKE','%'.$_GET['q'].'%');
if(!empty($_GET['min'])) $q->where('price','>=',(float)$_GET['min']);
if(!empty($_GET['max'])) $q->where('price','<=',(float)$_GET['max']);
$results = $q->orderBy('price','asc')->getAll();
```

---
## 11. Raw SQL Seguro (cuando lo necesitas)
```php
$rows = $orm->exec('SELECT id,name FROM users WHERE email LIKE ?', ['%@gmail.com']);
```
Usa `exec` para casos especiales; para lo demás prefiere el Query Builder.

---
## 12. Errores Comunes y Soluciones
| Situación | Causa | Solución |
|-----------|-------|----------|
| Campos `null` inesperados | No seteaste propiedad antes de `store()` | Asigna todas las propiedades requeridas |
| Excepción de validación | Regla falló | Captura `VersaORMException` y muestra mensaje |
| Consulta lenta | Falta índice en DB | Crea índice en la columna filtrada |

---
## 13. Próximos Pasos
- Leer `../user-guide/02-query-builder.md` para más patrones.
- Activar reglas de validación en tus modelos.
- Cuando el núcleo nativo esté listo, solo habilitar configuración— el código de arriba seguirá funcionando.

---
> ¿Algo falta en esta guía? Abre un issue o PR y mejorémoslo juntos.
