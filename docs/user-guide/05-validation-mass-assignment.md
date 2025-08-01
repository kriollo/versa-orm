# Validación y Mass Assignment

La seguridad y la integridad de los datos son fundamentales en cualquier aplicación. VersaORM incluye un sistema robusto de validación y protección contra Mass Assignment que te ayuda a mantener tus datos seguros y consistentes.

## ¿Qué es Mass Assignment?

Mass Assignment es la práctica de asignar múltiples atributos a un modelo de una sola vez usando un array. Si bien es conveniente, puede ser peligroso si no se controla adecuadamente, ya que usuarios malintencionados podrían modificar campos que no deberían ser editables.

### Ejemplo del Problema

```php
// ¡PELIGROSO! Sin protección
$user = new User();
$user->fill($_POST); // Un usuario podría enviar is_admin=1
$user->store();
```

## Protección Mass Assignment

VersaORM ofrece dos enfoques para proteger contra Mass Assignment vulnerabilities:

### 1. Lista Blanca con `$fillable`

Define explícitamente qué campos pueden ser asignados masivamente:

```php
class User extends BaseModel
{
    protected string $table = 'users';

    // Solo estos campos pueden ser asignados masivamente
    protected array $fillable = [
        'name',
        'email',
        'password',
        'bio'
    ];
}
```

**Uso seguro:**
```php
$user = new User();
$user->fill([
    'name' => 'Ana García',
    'email' => 'ana@example.com',
    'is_admin' => true // ¡Esto será RECHAZADO!
]);
// VersaORMException: Field 'is_admin' is not fillable
```

### 2. Lista Negra con `$guarded`

Define qué campos están protegidos contra Mass Assignment:

```php
class User extends BaseModel
{
    protected string $table = 'users';

    // Estos campos están protegidos
    protected array $guarded = [
        'id',
        'is_admin',
        'created_at',
        'updated_at'
    ];
}
```

### 3. Protección Total con Wildcard

Para proteger todos los campos por defecto:

```php
class User extends BaseModel
{
    protected array $guarded = ['*']; // Todos los campos protegidos
}
```

## Sistema de Validación

VersaORM incluye un sistema de validación completo que se ejecuta automáticamente antes de guardar datos.

### Validación Automática en `store()`

```php
$user = new User();
$user->fill([
    'name' => '', // Campo vacío
    'email' => 'email-invalido' // Email malformado
]);

try {
    $user->store(); // Validación automática
} catch (VersaORMException $e) {
    echo "Errores de validación: " . $e->getMessage();
    // Accede a los errores específicos
    $errors = $e->getContext()['errors'];
}
```

### Reglas de Validación Personalizadas

Define reglas específicas para cada campo en tu modelo:

```php
class User extends BaseModel
{
    protected string $table = 'users';

    protected array $fillable = [
        'name', 'email', 'password', 'age', 'phone'
    ];

    protected array $rules = [
        'name' => ['required', 'min:2', 'max:50'],
        'email' => ['required', 'email'],
        'password' => ['required', 'min:8'],
        'age' => ['numeric'],
        'phone' => ['required']
    ];
}
```

### Reglas Disponibles

| Regla | Descripción | Ejemplo |
|-------|-------------|---------|
| `required` | Campo obligatorio | `'name' => ['required']` |
| `email` | Formato de email válido | `'email' => ['email']` |
| `numeric` | Solo números | `'age' => ['numeric']` |
| `min:n` | Longitud mínima | `'password' => ['min:8']` |
| `max:n` | Longitud máxima | `'name' => ['max:50']` |

### Validación Manual

También puedes validar manualmente sin guardar:

```php
$user = new User();
$user->fill([
    'name' => 'Ana',
    'email' => 'ana@example.com'
]);

$errors = $user->validate();
if (empty($errors)) {
    echo "¡Datos válidos!";
    $user->store();
} else {
    foreach ($errors as $error) {
        echo "Error: $error\n";
    }
}
```

## Métodos de Asignación Segura

### `fill()` - Llenar con Protección

```php
$user = new User();
$user->fill($request->all()); // Solo campos $fillable
```

### `update()` - Actualizar con Validación

```php
$user = User::find(1);
$user->update([
    'name' => 'Nuevo Nombre',
    'email' => 'nuevo@email.com'
]); // Aplica fill() + validate() + store()
```

### `create()` - Crear con Mass Assignment

```php
$user = User::create([
    'name' => 'Luis Pérez',
    'email' => 'luis@example.com',
    'password' => 'secreto123'
]); // Crea instancia + fill() + retorna objeto
```

## Métodos de Verificación

### Verificar si un Campo es Fillable

```php
$user = new User();

if ($user->isFillable('email')) {
    echo "Email puede ser asignado masivamente";
}

if ($user->isGuarded('is_admin')) {
    echo "is_admin está protegido";
}
```

### Obtener Listas de Campos

```php
$fillableFields = $user->getFillable();
// ['name', 'email', 'password', 'bio']

$guardedFields = $user->getGuarded();
// ['id', 'is_admin', 'created_at', 'updated_at']
```

## Ejemplos Prácticos

### Registro de Usuario

```php
class User extends BaseModel
{
    protected string $table = 'users';

    protected array $fillable = [
        'name', 'email', 'password'
    ];

    protected array $rules = [
        'name' => ['required', 'min:2', 'max:50'],
        'email' => ['required', 'email'],
        'password' => ['required', 'min:8']
    ];

    // Lógica adicional
    public function setPassword(string $password): void
    {
        $this->password = password_hash($password, PASSWORD_DEFAULT);
    }
}

// Controlador de registro
try {
    $user = new User();
    $user->fill($request->all());
    $user->setPassword($user->password); // Hash del password
    $user->store(); // Validación automática

    return response()->json(['message' => 'Usuario creado exitosamente']);
} catch (VersaORMException $e) {
    return response()->json([
        'error' => 'Errores de validación',
        'details' => $e->getContext()['errors']
    ], 400);
}
```

### Actualización de Perfil

```php
class Profile extends BaseModel
{
    protected string $table = 'profiles';

    protected array $fillable = [
        'bio', 'website', 'location', 'birth_date'
    ];

    protected array $guarded = [
        'id', 'user_id', 'verified_at'
    ];

    protected array $rules = [
        'bio' => ['max:500'],
        'website' => ['max:255'],
        'location' => ['max:100']
    ];
}

// Actualización segura
$profile = Profile::find($userId);
$profile->update($request->only([
    'bio', 'website', 'location', 'birth_date'
])); // Solo campos permitidos
```

### Producto de E-commerce

```php
class Product extends BaseModel
{
    protected string $table = 'products';

    protected array $fillable = [
        'name', 'description', 'price', 'category_id'
    ];

    protected array $guarded = [
        'id', 'slug', 'created_at', 'updated_at', 'sales_count'
    ];

    protected array $rules = [
        'name' => ['required', 'min:3', 'max:100'],
        'description' => ['required', 'min:10'],
        'price' => ['required', 'numeric'],
        'category_id' => ['required', 'numeric']
    ];

    public function generateSlug(): void
    {
        $this->slug = strtolower(str_replace(' ', '-', $this->name));
    }
}
```

## Integración con Rust CLI

VersaORM también puede derivar reglas de validación automáticamente desde el esquema de la base de datos usando su núcleo Rust:

```php
// Futuras funcionalidades automáticas basadas en esquema
$user = new User();
$schemaRules = $user->getSchemaValidationRules();
// Reglas automáticas basadas en NOT NULL, VARCHAR(255), etc.
```

## Buenas Prácticas

### 1. Siempre Define Mass Assignment Protection

```php
// ✅ BUENO: Protección explícita
class User extends BaseModel
{
    protected array $fillable = ['name', 'email'];
}

// ❌ MALO: Sin protección
class User extends BaseModel
{
    // Sin $fillable ni $guarded = peligroso
}
```

### 2. Usa Validación en Todos los Modelos Críticos

```php
// ✅ BUENO: Validación completa
protected array $rules = [
    'email' => ['required', 'email'],
    'password' => ['required', 'min:8']
];

// ❌ MALO: Sin validación
// Confiar solo en validación del frontend
```

### 3. Combina Fillable con Validación

```php
// ✅ BUENO: Doble protección
protected array $fillable = ['name', 'email'];
protected array $rules = [
    'name' => ['required', 'max:50'],
    'email' => ['required', 'email']
];
```

### 4. Maneja Errores Apropiadamente

```php
// ✅ BUENO: Manejo de errores robusto
try {
    $user->store();
} catch (VersaORMException $e) {
    Log::error('Validation failed', $e->getContext());
    return response()->json([
        'error' => 'Datos inválidos',
        'details' => $e->getContext()['errors']
    ], 422);
}
```

## Siguiente Paso

Continúa con la [Herramienta de Línea de Comandos (CLI)](04-cli-tool.md) para aprender sobre las capacidades avanzadas del núcleo Rust de VersaORM.
