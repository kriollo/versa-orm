# Model Class

La clase `Model` implementa el patrón ActiveRecord, proporcionando una interfaz orientada a objetos para trabajar con registros de base de datos individuales.

## Tabla de Contenidos

- [Constructor](#constructor)
- [Configuración Global](#configuración-global)
- [Carga de Datos](#carga-de-datos)
- [Operaciones CRUD](#operaciones-crud)
- [Acceso a Propiedades](#acceso-a-propiedades)
- [Exportación de Datos](#exportación-de-datos)
- [Métodos Estáticos](#métodos-estáticos)
- [Utilidades](#utilidades)

---

## Constructor

### `__construct(string $table, $orm)`

Crea una nueva instancia de Model.

**Parámetros:**
- `$table` (string): Nombre de la tabla
- `$orm` (VersaORM|array): Instancia de VersaORM o configuración de base de datos

**Ejemplo:**
```php
use VersaORM\Model;
use VersaORM\VersaORM;

$orm = new VersaORM($config);
$user = new Model('users', $orm);
```

---

## Configuración Global

### `setORM(VersaORM $orm): void`

Configura la instancia global del ORM para métodos estáticos.

**Parámetros:**
- `$orm` (VersaORM): Instancia del ORM

**Ejemplo:**
```php
Model::setORM($orm);

// Ahora se pueden usar métodos estáticos
$user = Model::load('users', 1);
$newUser = Model::dispense('users');
```

---

## Carga de Datos

### `loadInstance($data, string $pk = 'id'): self`

Carga datos en la instancia del modelo (método de instancia).

**Parámetros:**
- `$data` (mixed): Array de datos o ID para buscar
- `$pk` (string, opcional): Nombre de la clave primaria

**Retorna:** La instancia actual del modelo

**Ejemplos:**
```php
// Cargar desde array de datos
$user = new Model('users', $orm);
$user->loadInstance([
    'id' => 1,
    'name' => 'Juan Pérez',
    'email' => 'juan@ejemplo.com'
]);

// Cargar desde ID (busca en base de datos)
$user = new Model('users', $orm);
$user->loadInstance(1); // Busca user con id = 1

// Cargar por clave primaria personalizada
$product = new Model('products', $orm);
$product->loadInstance('SKU123', 'sku');
```

---

## Operaciones CRUD

### `store(): void`

Guarda el modelo en la base de datos (INSERT o UPDATE automático).

**Comportamiento:**
- Si el modelo tiene ID, realiza UPDATE
- Si no tiene ID, realiza INSERT y actualiza el ID

**Ejemplo:**
```php
// Crear nuevo registro
$user = new Model('users', $orm);
$user->name = 'Ana García';
$user->email = 'ana@ejemplo.com';
$user->status = 'active';
$user->store(); // INSERT

echo $user->id; // ID del nuevo registro

// Modificar registro existente
$user->name = 'Ana García López';
$user->store(); // UPDATE
```

### `trash(): void`

Elimina el registro del modelo de la base de datos.

**Requisitos:**
- El modelo debe tener un ID

**Ejemplo:**
```php
$user = new Model('users', $orm);
$user->loadInstance(1);

$user->trash(); // DELETE FROM users WHERE id = 1

// Los atributos se limpian después de eliminar
echo count($user->getData()); // 0
```

---

## Acceso a Propiedades

### `__set(string $key, $value): void`

Asigna valor a un atributo del modelo.

**Parámetros:**
- `$key` (string): Nombre del atributo
- `$value` (mixed): Valor a asignar

**Ejemplo:**
```php
$user = new Model('users', $orm);
$user->name = 'Carlos Ruiz';
$user->email = 'carlos@ejemplo.com';
$user->age = 25;
$user->active = true;
```

### `__get(string $key): mixed`

Obtiene el valor de un atributo del modelo.

**Parámetros:**
- `$key` (string): Nombre del atributo

**Retorna:** Valor del atributo o null si no existe

**Ejemplo:**
```php
$user->loadInstance(1);

echo $user->name;    // Juan Pérez
echo $user->email;   // juan@ejemplo.com
echo $user->age;     // 30
echo $user->missing; // null
```

### `__isset(string $key): bool`

Verifica si existe un atributo.

**Parámetros:**
- `$key` (string): Nombre del atributo

**Retorna:** true si el atributo existe

**Ejemplo:**
```php
if (isset($user->email)) {
    echo "El usuario tiene email: " . $user->email;
}

$hasAge = isset($user->age);
$hasPhone = isset($user->phone);
```

### `__unset(string $key): void`

Elimina un atributo del modelo.

**Parámetros:**
- `$key` (string): Nombre del atributo

**Ejemplo:**
```php
unset($user->temporary_field);

// Útil para limpiar campos antes de guardar
unset($user->confirm_password);
$user->store();
```

---

## Exportación de Datos

### `export(): array`

Exporta el modelo a un array asociativo.

**Retorna:** Array con todos los atributos del modelo

**Ejemplo:**
```php
$user->loadInstance(1);
$userData = $user->export();

/*
Array:
[
    'id' => 1,
    'name' => 'Juan Pérez',
    'email' => 'juan@ejemplo.com',
    'created_at' => '2024-01-15 10:30:00',
    'updated_at' => '2024-01-20 14:45:00'
]
*/

// Útil para JSON APIs
header('Content-Type: application/json');
echo json_encode($user->export());
```

### `exportAll(array $models): array`

Exporta una colección de modelos a un array de arrays (método estático).

**Parámetros:**
- `$models` (array): Array de instancias de Model

**Retorna:** Array de arrays con los datos

**Ejemplo:**
```php
$users = $orm->findAll('users', 'active = 1');
$usersData = Model::exportAll($users);

/*
Array:
[
    ['id' => 1, 'name' => 'Juan', 'email' => 'juan@ejemplo.com'],
    ['id' => 2, 'name' => 'Ana', 'email' => 'ana@ejemplo.com'],
    ['id' => 3, 'name' => 'Carlos', 'email' => 'carlos@ejemplo.com']
]
*/

// Para APIs REST
header('Content-Type: application/json');
echo json_encode(Model::exportAll($users));
```

---

## Métodos Estáticos

### `dispense(string $table): self`

Crea un nuevo modelo vacío (método estático).

**Parámetros:**
- `$table` (string): Nombre de la tabla

**Retorna:** Nueva instancia de Model

**Requisito:** Debe haberse llamado `Model::setORM()` previamente

**Ejemplo:**
```php
Model::setORM($orm);

$user = Model::dispense('users');
$user->name = 'María González';
$user->email = 'maria@ejemplo.com';
$user->store();
```

### `load(string $table, $id, string $pk = 'id'): ?self`

Carga un modelo por ID (método estático).

**Parámetros:**
- `$table` (string): Nombre de la tabla
- `$id` (mixed): Valor del ID a buscar
- `$pk` (string, opcional): Nombre de la clave primaria

**Retorna:** Instancia de Model o null si no se encuentra

**Ejemplo:**
```php
Model::setORM($orm);

// Cargar por ID
$user = Model::load('users', 1);
if ($user) {
    echo "Usuario: " . $user->name;
} else {
    echo "Usuario no encontrado";
}

// Cargar por clave primaria personalizada
$product = Model::load('products', 'SKU123', 'sku');
```

---

## Utilidades

### `getTable(): string`

Obtiene el nombre de la tabla del modelo.

**Retorna:** Nombre de la tabla

**Ejemplo:**
```php
$user = new Model('users', $orm);
echo $user->getTable(); // users

$product = new Model('products', $orm);
echo $product->getTable(); // products
```

### `getData(): array`

Obtiene todos los datos del modelo como array.

**Retorna:** Array con todos los atributos

**Ejemplo:**
```php
$user->loadInstance(1);
$allData = $user->getData();

echo "Campos disponibles: " . implode(', ', array_keys($allData));
echo "Total de campos: " . count($allData);
```

### `dispenseInstance(string $table): self`

Crea un nuevo modelo vacío usando la configuración de la instancia actual.

**Parámetros:**
- `$table` (string): Nombre de la tabla

**Retorna:** Nueva instancia de Model

**Ejemplo:**
```php
$user = new Model('users', $orm);

// Crear otros modelos usando la misma configuración
$profile = $user->dispenseInstance('profiles');
$profile->user_id = $user->id;
$profile->bio = 'Desarrollador PHP';
$profile->store();
```

---

## Ejemplos Avanzados

### Patrón ActiveRecord Completo

```php
// Configurar ORM global
Model::setORM($orm);

// Crear usuario
$user = Model::dispense('users');
$user->name = 'Pedro Martínez';
$user->email = 'pedro@ejemplo.com';
$user->password = password_hash('secreto', PASSWORD_DEFAULT);
$user->status = 'active';
$user->store();

echo "Usuario creado con ID: " . $user->id;

// Cargar y modificar
$user = Model::load('users', $user->id);
$user->last_login = date('Y-m-d H:i:s');
$user->login_count = ($user->login_count ?? 0) + 1;
$user->store();

// Exportar para API
header('Content-Type: application/json');
echo json_encode($user->export());
```

### Trabajo con Relaciones (Manual)

```php
// Cargar usuario con sus posts
$user = Model::load('users', 1);
$posts = $orm->findAll('posts', 'user_id = ?', [$user->id]);

$userData = $user->export();
$userData['posts'] = Model::exportAll($posts);

echo json_encode($userData);
```

### Validación Personalizada

```php
class UserModel extends Model
{
    public function validate(): array
    {
        $errors = [];
        
        if (empty($this->name)) {
            $errors[] = 'El nombre es requerido';
        }
        
        if (empty($this->email)) {
            $errors[] = 'El email es requerido';
        } elseif (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'El email no es válido';
        }
        
        return $errors;
    }
    
    public function store(): void
    {
        $errors = $this->validate();
        if (!empty($errors)) {
            throw new Exception('Errores de validación: ' . implode(', ', $errors));
        }
        
        parent::store();
    }
}

// Uso
$user = new UserModel('users', $orm);
$user->name = '';
$user->email = 'email-invalido';

try {
    $user->store();
} catch (Exception $e) {
    echo $e->getMessage();
    // Errores de validación: El nombre es requerido, El email no es válido
}
```

### Campos Automáticos

```php
class TimestampedModel extends Model
{
    public function store(): void
    {
        $now = date('Y-m-d H:i:s');
        
        if (!isset($this->id)) {
            // Nuevo registro
            $this->created_at = $now;
        }
        
        // Siempre actualizar updated_at
        $this->updated_at = $now;
        
        parent::store();
    }
}

// Uso
$article = new TimestampedModel('articles', $orm);
$article->title = 'Mi Artículo';
$article->content = 'Contenido del artículo...';
$article->store(); // created_at y updated_at se establecen automáticamente
```

### Soft Deletes

```php
class SoftDeleteModel extends Model
{
    public function trash(): void
    {
        // En lugar de eliminar, marcar como eliminado
        $this->deleted_at = date('Y-m-d H:i:s');
        $this->store();
    }
    
    public function restore(): void
    {
        unset($this->deleted_at);
        $this->store();
    }
    
    public function isDeleted(): bool
    {
        return isset($this->deleted_at);
    }
}

// Uso
$user = new SoftDeleteModel('users', $orm);
$user->loadInstance(1);

$user->trash();     // Marca como eliminado
$user->restore();   // Restaura el registro
```

---

## Patrones de Uso Comunes

### 1. Factory Pattern

```php
class ModelFactory
{
    private $orm;
    
    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
    }
    
    public function createUser(array $data): Model
    {
        $user = new Model('users', $this->orm);
        foreach ($data as $key => $value) {
            $user->$key = $value;
        }
        $user->store();
        return $user;
    }
}

// Uso
$factory = new ModelFactory($orm);
$user = $factory->createUser([
    'name' => 'Luis Rodríguez',
    'email' => 'luis@ejemplo.com'
]);
```

### 2. Repository Pattern

```php
class UserRepository
{
    private $orm;
    
    public function __construct(VersaORM $orm)
    {
        $this->orm = $orm;
    }
    
    public function findActive(): array
    {
        return $this->orm->findAll('users', 'status = ?', ['active']);
    }
    
    public function findByEmail(string $email): ?Model
    {
        $users = $this->orm->findAll('users', 'email = ?', [$email]);
        return $users[0] ?? null;
    }
    
    public function create(array $data): Model
    {
        $user = new Model('users', $this->orm);
        foreach ($data as $key => $value) {
            $user->$key = $value;
        }
        $user->store();
        return $user;
    }
}
```

---

## Consideraciones de Rendimiento

1. **Lazy Loading**: Los modelos solo cargan datos cuando es necesario
2. **Batch Operations**: Para múltiples operaciones, considerar QueryBuilder
3. **Memory Usage**: Los modelos mantienen datos en memoria hasta que se liberen
4. **Validación**: Implementar validación personalizada para datos críticos

---

Esta documentación cubre todas las funcionalidades de la clase Model. Para casos de uso más específicos, consulta los ejemplos y patrones en la documentación.
