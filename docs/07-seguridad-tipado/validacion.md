# Validación en VersaORM

VersaORM proporciona un sistema robusto de validación que te permite definir reglas automáticas y personalizadas para garantizar la integridad de los datos antes de que se guarden en la base de datos.

## ¿Qué es la Validación?

La validación es el proceso de verificar que los datos cumplan con ciertas reglas antes de ser almacenados.rsaORM ofrece:

- **Validación Automática**: Basada en tipos de datos y restricciones de base de datos
- **Validación Personalizada**: Reglas específicas definidas por el desarrollador
- **Validación en Tiempo Real**: Se ejecuta antes de cada operación de guardado
- **Mensajes de Error Descriptivos**: Para facilitar la depuración y experiencia del usuario

## Validación Automática

### Validación por Tipo de Dato

```php
// Configuración básica
$orm = new VersaORM([
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'password'
]);

// VersaORM valida automáticamente los tipos
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';     // ✅ String válido
$user->age = 25;                // ✅ Integer válido
$user->email = 'juan@test.com'; // ✅ String válido

try {
    $user->age = 'veinticinco';  // ❌ String en campo integer
    $user->store();
} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage();
    // Error: El campo 'age' debe ser un número entero
}
```

### Validación de Longitud

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    // Definir longitudes máximas
    protected static $maxLength = [
        'name' => 100,
        'email' => 255,
        'phone' => 20
    ];

    // Definir longitudes mínimas
    protected static $minLength = [
        'name' => 2,
        'password' => 8
    ];
}

// Uso con validación automática
$user = new UserModel();
$user->name = 'A';  // ❌ Muy corto (mínimo 2 caracteres)
$user->email = str_repeat('a', 300); // ❌ Muy largo (máximo 255)

try {
    $user->save();
} catch (VersaORMException $e) {
    echo $e->getMessage();
    // El campo 'name' debe tener al menos 2 caracteres
}
```

## Validación Personalizada

### Reglas Básicas en el Modelo

```php
class ProductModel extends VersaModel {
    protected static $table = 'products';

    // Definir reglas de validación
    protected static $rules = [
        'name' => 'required|string|min:3|max:100',
        'price' => 'required|numeric|min:0.01',
        'category_id' => 'required|integer|exists:categories,id',
        'email' => 'email',
        'website' => 'url'
    ];

    // Mensajes personalizados
    protected static $messages = [
        'name.required' => 'El nombre del producto es obligatorio',
        'name.min' => 'El nombre debe tener al menos 3 caracteres',
        'price.min' => 'El precio debe ser mayor a cero',
        'email.email' => 'Debe proporcionar un email válido'
    ];
}
```

### Uso de Validación con Reglas

```php
$product = new ProductModel();
$product->name = 'TV';           // ❌ Muy corto
$product->price = -100;          // ❌ Precio negativo
$product->email = 'no-es-email'; // ❌ Email inválido

try {
    $product->save();
} catch (VersaORMException $e) {
    $errors = $e->getValidationErrors();
    foreach ($errors as $field => $messages) {
        echo "$field: " . implode(', ', $messages) . "\n";
    }
    // name: El nombre debe tener al menos 3 caracteres
    // price: El precio debe ser mayor a cero
    // email: Debe proporcionar un email válido
}
```

## Reglas de Validación Disponibles

### Reglas Básicas

```php
protected static $rules = [
    // Requerido
    'name' => 'required',

    // Tipos de datos
    'age' => 'integer',
    'price' => 'numeric',
    'active' => 'boolean',
    'email' => 'email',
    'website' => 'url',

    // Longitud
    'password' => 'min:8|max:50',
    'description' => 'max:500',

    // Valores específicos
    'status' => 'in:active,inactive,pending',
    'rating' => 'between:1,5',

    // Expresiones regulares
    'phone' => 'regex:/^[0-9]{10}$/',
    'slug' => 'regex:/^[a-z0-9-]+$/'
];
```

### Reglas de Relación

```php
protected static $rules = [
    // Verificar que existe en otra tabla
    'category_id' => 'exists:categories,id',
    'user_id' => 'exists:users,id',

    // Verificar que es único
    'email' => 'unique:users,email',
    'slug' => 'unique:posts,slug',

    // Único excepto el registro actual (para updates)
    'email' => 'unique:users,email,{id}'
];
```

## Validación Personalizada Avanzada

### Métodos de Validación Personalizados

```php
class OrderModel extends VersaModel {
    protected static $table = 'orders';

    // Validación personalizada antes de guardar
    public function beforeStore() {
        // Validar que la fecha de entrega sea futura
        if ($this->delivery_date && $this->delivery_date <= date('Y-m-d')) {
            throw new VersaORMException('La fecha de entrega debe ser futura');
        }

        // Validar que el total coincida con los items
        if ($this->total != $this->calculateTotal()) {
            throw new VersaORMException('El total no coincide con los items');
        }

        // Validar stock disponible
        if (!$this->hasAvailableStock()) {
            throw new VersaORMException('Stock insuficiente para algunos productos');
        }

        return true;
    }

    private function calculateTotal() {
        $total = 0;
        foreach ($this->items as $item) {
            $total += $item->price * $item->quantity;
        }
        return $total;
    }

    private function hasAvailableStock() {
        foreach ($this->items as $item) {
            $product = $this->orm->load('products', $item->product_id);
            if ($product->stock < $item->quantity) {
                return false;
            }
        }
        return true;
    }
}
```

### Validadores Personalizados

```php
class CustomValidator {
    // Validar número de teléfono mexicano
    public static function mexicanPhone($value) {
        return preg_match('/^(\+52|52)?[1-9]\d{9}$/', $value);
    }

    // Validar RFC mexicano
    public static function rfc($value) {
        $pattern = '/^[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}$/';
        return preg_match($pattern, strtoupper($value));
    }

    // Validar que la fecha sea día laboral
    public static function workday($value) {
        $date = new DateTime($value);
        $dayOfWeek = $date->format('N'); // 1 = Lunes, 7 = Domingo
        return $dayOfWeek >= 1 && $dayOfWeek <= 5;
    }
}

// Registrar validadores personalizados
$orm->addValidator('mexican_phone', [CustomValidator::class, 'mexicanPhone']);
$orm->addValidator('rfc', [CustomValidator::class, 'rfc']);
$orm->addValidator('workday', [CustomValidator::class, 'workday']);

// Usar en el modelo
class CompanyModel extends VersaModel {
    protected static $rules = [
        'phone' => 'mexican_phone',
        'rfc' => 'required|rfc',
        'meeting_date' => 'workday'
    ];
}
```

## Validación Condicional

### Validación Basada en Condiciones

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    public function beforeStore() {
        // Validar email solo si el usuario es activo
        if ($this->active && empty($this->email)) {
            throw new VersaORMException('Los usuarios activos deben tener email');
        }

        // Validar contraseña solo para nuevos usuarios
        if ($this->isNew() && empty($this->password)) {
            throw new VersaORMException('La contraseña es requerida para nuevos usuarios');
        }

        // Validar rol según el tipo de usuario
        if ($this->type === 'admin' && !in_array($this->role, ['super_admin', 'admin'])) {
            throw new VersaORMException('Rol inválido para usuario administrador');
        }

        return true;
    }
}
```

### Validación por Grupos

```php
class EventModel extends VersaModel {
    protected static $table = 'events';

    // Diferentes reglas según el contexto
    public function validate($context = 'default') {
        switch ($context) {
            case 'draft':
                return $this->validateDraft();
            case 'publish':
                return $this->validatePublish();
            case 'archive':
                return $this->validateArchive();
            default:
                return $this->validateDefault();
        }
    }

    private function validateDraft() {
        // Solo validar campos básicos para borradores
        if (empty($this->title)) {
            throw new VersaORMException('El título es requerido');
        }
        return true;
    }

    private function validatePublish() {
        // Validación completa para publicar
        $required = ['title', 'description', 'start_date', 'location'];
        foreach ($required as $field) {
            if (empty($this->$field)) {
                throw new VersaORMException("El campo '$field' es requerido para publicar");
            }
        }

        if ($this->start_date <= date('Y-m-d H:i:s')) {
            throw new VersaORMException('La fecha de inicio debe ser futura');
        }

        return true;
    }
}

// Uso con contexto específico
$event = new EventModel();
$event->title = 'Mi Evento';
$event->validate('draft');    // ✅ Válido para borrador
$event->validate('publish');  // ❌ Falta información para publicar
```

## Validación de Arrays y JSON

### Validar Estructura de Arrays

```php
class ConfigModel extends VersaModel {
    protected static $table = 'configurations';

    public function beforeStore() {
        // Validar que settings sea un array válido
        if (!is_array($this->settings)) {
            throw new VersaORMException('Settings debe ser un array');
        }

        // Validar estructura requerida
        $required = ['theme', 'language', 'timezone'];
        foreach ($required as $key) {
            if (!isset($this->settings[$key])) {
                throw new VersaORMException("Falta configuración requerida: $key");
            }
        }

        // Validar valores específicos
        $validThemes = ['light', 'dark', 'auto'];
        if (!in_array($this->settings['theme'], $validThemes)) {
            throw new VersaORMException('Tema inválido');
        }

        return true;
    }
}
```

### Validar Elementos de Array

```php
class OrderModel extends VersaModel {
    protected static $table = 'orders';

    public function beforeStore() {
        // Validar que items no esté vacío
        if (empty($this->items) || !is_array($this->items)) {
            throw new VersaORMException('La orden debe tener al menos un item');
        }

        // Validar cada item
        foreach ($this->items as $index => $item) {
            if (!isset($item['product_id']) || !isset($item['quantity'])) {
                throw new VersaORMException("Item $index incompleto");
            }

            if ($item['quantity'] <= 0) {
                throw new VersaORMException("Cantidad inválida en item $index");
            }

            // Verificar que el producto existe
            $product = $this->orm->load('products', $item['product_id']);
            if ($model === null) {
                throw new VersaORMException("Producto no encontrado en item $index");
            }
        }

        return true;
    }
}
```

## Manejo de Errores de Validación

### Capturar y Mostrar Errores

```php
function createUser($data) {
    try {
        $user = new UserModel();
        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->age = $data['age'];

        $user->save();

        return ['success' => true, 'user' => $user];

    } catch (VersaORMException $e) {
        // Obtener errores específicos de validación
        $errors = $e->getValidationErrors();

        return [
            'success' => false,
            'message' => 'Errores de validación',
            'errors' => $errors
        ];
    }
}

// Uso
$result = createUser([
    'name' => 'A',              // Muy corto
    'email' => 'no-es-email',   // Email inválido
    'age' => 'veinticinco'      // Tipo incorrecto
]);

if (!$result['success']) {
    foreach ($result['errors'] as $field => $messages) {
        echo "$field: " . implode(', ', $messages) . "\n";
    }
}
```

### Validación en Lote

```php
function validateMultipleUsers($usersData) {
    $results = [];
    $errors = [];

    foreach ($usersData as $index => $userData) {
        try {
            $user = new UserModel();
            $user->fill($userData);
            $user->validate(); // Solo validar, no guardar

            $results[$index] = ['valid' => true];

        } catch (VersaORMException $e) {
            $results[$index] = [
                'valid' => false,
                'errors' => $e->getValidationErrors()
            ];
            $errors[] = $index;
        }
    }

    return [
        'results' => $results,
        'hasErrors' => !empty($errors),
        'errorCount' => count($errors)
    ];
}
```

## Mejores Prácticas

### 1. Validar en el Modelo, No en el Controlador

```php
// ✅ Buena práctica: Validación en el modelo
class UserModel extends VersaModel {
    public function beforeStore() {
        if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            throw new VersaORMException('Email inválido');
        }
        return true;
    }
}

// ❌ Evitar: Validación solo en el controlador
class UserController {
    public function create($data) {
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return ['error' => 'Email inválido'];
        }
        // La validación debería estar en el modelo
    }
}
```

### 2. Usar Mensajes Descriptivos

```php
// ✅ Buena práctica: Mensajes claros
protected static $messages = [
    'email.required' => 'El email es obligatorio',
    'email.email' => 'Debe proporcionar un email válido',
    'password.min' => 'La contraseña debe tener al menos 8 caracteres'
];

// ❌ Evitar: Mensajes genéricos o técnicos
```

### 3. Validar Datos Relacionados

```php
// ✅ Buena práctica: Validar relaciones
public function beforeStore() {
    if ($this->category_id) {
        $category = $this->orm->load('categories', $this->category_id);
        if ($model === null) {
            throw new VersaORMException('Categoría no encontrada');
        }
        if (!$category->active) {
            throw new VersaORMException('No se puede asignar una categoría inactiva');
        }
    }
    return true;
}
```

## Errores Comunes

### Error: Validación Circular

```php
// ❌ Error común: Validación que se llama a sí misma
public function beforeStore() {
    $this->save(); // Esto causará un bucle infinito
}

// ✅ Solución: Usar métodos específicos de validación
public function beforeStore() {
    $this->validateBusinessRules();
    return true;
}
```

### Error: No Manejar Excepciones

```php
// ❌ Error común: No capturar errores de validación
$user = new UserModel();
$user->email = 'invalid-email';
$user->save(); // Puede lanzar excepción no manejada

// ✅ Solución: Siempre manejar excepciones
try {
    $user->save();
} catch (VersaORMException $e) {
    // Manejar error apropiadamente
}
```

La validación en VersaORM te ayuda a mantener la integridad de los datos y proporcionar una mejor experiencia al usuario con mensajes de error claros y específicos.

## Siguiente Paso

Continúa con [Protección Mass Assignment](mass-assignment.md) para aprender cómo proteger tu aplicación contra asignación masiva no autorizada.