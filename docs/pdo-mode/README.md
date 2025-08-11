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
## 4. Joins y Selección Parcial
```php
$posts = $orm->table('posts')
  ->select(['posts.id','posts.title','u.name AS author'])
  ->join('users AS u','u.id','=','posts.user_id')
  ->where('posts.published','=',1)
  ->orderBy('posts.created_at','desc')
  ->getAll();
```

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
