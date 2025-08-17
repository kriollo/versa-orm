# Tipado Estricto en VersaORM

VersaORM implementa un sistema de tipado estricto que convierte automáticamente los datos entre PHP y la base de datos, garantizando la integridad y consistencia de la información.

## ¿Qué es el Tipado Estricto?

El tipado estricto es un sistema que:
- Convierte automáticamente los tipos de datos
- Valida que los datos cumplan con el tipo esperado
- Previene errores de tipo en tiempo de ejecución
- Mantiene consistencia entre diferentes motores de base de datos

## Conversión Automática de Tipos

### Tipos Básicos Soportados

```php
// Configuración de ejemplo
$orm = new VersaORM([
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'password'
]);

// Crear un usuario con diferentes tipos de datos
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';           // STRING
$user->age = 25;                      // INTEGER
$user->salary = 2500.50;              // FLOAT/DECIMAL
$user->active = true;                 // BOOLEAN
$user->created_at = new DateTime();   // DATETIME
$user->metadata = ['role' => 'admin']; // JSON (si está soportado)

$id = $$user->store();
```

**SQL Equivalente:**
```sql
INSERT INTO users (name, age, salary, active, created_at, metadata)
VALUES ('Juan Pérez', 25, 2500.50, 1, '2024-01-15 10:30:00', '{"role":"admin"}');
```

### Conversión al Recuperar Datos

```php
// Al recuperar, VersaORM convierte automáticamente los tipos
$user = VersaModel::load('users', $id);

var_dump($user->name);        // string(10) "Juan Pérez"
var_dump($user->age);         // int(25)
var_dump($user->salary);      // float(2500.5)
var_dump($user->active);      // bool(true)
var_dump($user->created_at);  // object(DateTime)
var_dump($user->metadata);    // array(1) { ["role"]=> string(5) "admin" }
```

## Configuración de Tipos por Columna

### Definir Tipos Específicos

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    // Definir tipos específicos para columnas
    protected static $types = [
        'id' => 'integer',
        'name' => 'string',
        'email' => 'string',
        'age' => 'integer',
        'salary' => 'decimal',
        'active' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'metadata' => 'json',
        'score' => 'float'
    ];

    // Configurar precisión para decimales
    protected static $precision = [
        'salary' => [10, 2],  // 10 dígitos totales, 2 decimales
        'score' => [5, 3]     // 5 dígitos totales, 3 decimales
    ];
}
```

### Uso con Tipos Definidos

```php
$user = UserModel::create([
    'name' => 'Ana García',
    'email' => 'ana@example.com',
    'age' => '30',           // String será convertido a integer
    'salary' => '3500.75',   // String será convertido a decimal
    'active' => 'true',      // String será convertido a boolean
    'metadata' => '{"department":"IT"}' // String será convertido a array
]);

// VersaORM garantiza que los tipos sean correctos
echo gettype($user->age);     // integer
echo gettype($user->salary);  // double (float)
echo gettype($user->active);  // boolean
echo gettype($user->metadata); // array
```

## Validación de Tipos

### Validación Automática

```php
try {
    $user = VersaModel::dispense('users');
    $user->age = 'no es un número';  // Esto causará un error
    $$user->store();
} catch (VersaORMException $e) {
    echo "Error de tipo: " . $e->getMessage();
    // Error de tipo: El campo 'age' debe ser un número entero
}
```

### Validación Personalizada

```php
class ProductModel extends VersaModel {
    protected static $table = 'products';

    protected static $types = [
        'price' => 'decimal',
        'stock' => 'integer',
        'active' => 'boolean'
    ];

    // Validación personalizada antes de guardar
    public function beforeStore() {
        // Validar que el precio sea positivo
        if ($this->price <= 0) {
            throw new VersaORMException('El precio debe ser mayor a cero');
        }

        // Validar que el stock no sea negativo
        if ($this->stock < 0) {
            throw new VersaORMException('El stock no puede ser negativo');
        }

        return true;
    }
}
```

## Tipos Específicos por Motor de Base de datos

### MySQL

```php
// Configuración específica para MySQL
$mysqlTypes = [
    'id' => 'bigint',
    'uuid' => 'char(36)',
    'status' => 'enum',
    'tags' => 'set',
    'content' => 'longtext',
    'data' => 'json'
];
```

### PostgreSQL

```php
// Configuración específica para PostgreSQL
$postgresTypes = [
    'id' => 'bigserial',
    'uuid' => 'uuid',
    'ip_address' => 'inet',
    'data' => 'jsonb',
    'coordinates' => 'point',
    'range_dates' => 'daterange'
];
```

### SQLite

```php
// SQLite maneja tipos de forma más flexible
$sqliteTypes = [
    'id' => 'integer',
    'data' => 'text',  // JSON se almacena como texto
    'active' => 'integer' // Boolean se almacena como integer
];
```

## Conversión de Fechas y Tiempo

### Manejo Automático de DateTime

```php
$event = VersaModel::dispense('events');
$event->start_date = '2024-12-25';           // String a Date
$event->start_time = '14:30:00';             // String a Time
$event->created_at = new DateTime();         // DateTime object
$event->updated_at = time();                 // Timestamp a DateTime

$$event->store();

// Al recuperar, todo se convierte a DateTime objects
$retrieved = VersaModel::load('events', $event->id);
echo $retrieved->start_date->format('Y-m-d');     // 2024-12-25
echo $retrieved->created_at->format('Y-m-d H:i:s'); // 2024-01-15 10:30:00
```

### Zonas Horarias

```php
// Configurar zona horaria por defecto
$orm->setTimezone('America/Mexico_City');

$event = VersaModel::dispense('events');
$event->event_date = new DateTime('2024-12-25 15:00:00', new DateTimeZone('UTC'));

$$event->store();

// Al recuperar, se respeta la zona horaria configurada
$retrieved = VersaModel::load('events', $event->id);
echo $retrieved->event_date->getTimezone()->getName(); // America/Mexico_City
```

## Conversión de Arrays y JSON

### Manejo Automático de JSON

```php
$user = VersaModel::dispense('users');
$user->preferences = [
    'theme' => 'dark',
    'language' => 'es',
    'notifications' => true
];

$$user->store();

// En la base de datos se almacena como JSON
// {"theme":"dark","language":"es","notifications":true}

// Al recuperar, se convierte automáticamente a array
$retrieved = VersaModel::load('users', $user->id);
echo $retrieved->preferences['theme']; // dark
```

### Validación de Estructura JSON

```php
class ConfigModel extends VersaModel {
    protected static $table = 'configurations';

    protected static $types = [
        'settings' => 'json'
    ];

    // Validar estructura del JSON
    public function beforeStore() {
        if (!is_array($this->settings)) {
            throw new VersaORMException('Settings debe ser un array');
        }

        $required = ['theme', 'language'];
        foreach ($required as $key) {
            if (!isset($this->settings[$key])) {
                throw new VersaORMException("Falta la configuración requerida: $key");
            }
        }

        return true;
    }
}
```

## Mejores Prácticas

### 1. Definir Tipos Explícitamente

```php
// ✅ Buena práctica: Definir tipos explícitos
class OrderModel extends VersaModel {
    protected static $types = [
        'total' => 'decimal',
        'quantity' => 'integer',
        'shipped' => 'boolean',
        'created_at' => 'datetime'
    ];
}

// ❌ Evitar: Dejar que VersaORM adivine los tipos
```

### 2. Usar Validación Personalizada

```php
// ✅ Buena práctica: Validar datos antes de guardar
public function beforeStore() {
    if ($this->email && !filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
        throw new VersaORMException('Email inválido');
    }
    return true;
}
```

### 3. Manejar Errores de Tipo

```php
// ✅ Buena práctica: Capturar errores de tipo específicos
try {
    $user->age = $input['age'];
    $$user->store();
} catch (VersaORMException $e) {
    if (strpos($e->getMessage(), 'tipo') !== false) {
        // Manejar error de tipo específicamente
        $errors['age'] = 'La edad debe ser un número';
    }
}
```

## Errores Comunes

### Error: Tipo Incorrecto

```php
// ❌ Error común
$user = VersaModel::dispense('users');
$user->active = 'yes'; // String en lugar de boolean

// ✅ Solución
$user->active = ($input['active'] === 'yes'); // Convertir a boolean
```

### Error: Precisión Decimal

```php
// ❌ Error común: Perder precisión
$product->price = 19.999; // Se puede redondear

// ✅ Solución: Usar strings para decimales exactos
$product->price = '19.99';
```

### Error: Fechas Inválidas

```php
// ❌ Error común
$event->date = '2024-13-45'; // Fecha inválida

// ✅ Solución: Validar fechas
try {
    $event->date = new DateTime($input['date']);
} catch (Exception $e) {
    throw new VersaORMException('Fecha inválida');
}
```

## Configuración Avanzada

### Personalizar Conversores de Tipo

```php
// Registrar un conversor personalizado
$orm->addTypeConverter('money', function($value) {
    // Convertir string de dinero a float
    return (float) str_replace(['$', ','], '', $value);
});

// Usar el conversor personalizado
$product = VersaModel::dispense('products');
$product->price = '$1,299.99'; // Se convertirá a 1299.99
```

El tipado estricto en VersaORM te ayuda a mantener la integridad de los datos y prevenir errores comunes, mientras que la conversión automática simplifica el trabajo con diferentes tipos de datos entre PHP y la base de datos.

## Siguiente Paso

Continúa con [Validación](validacion.md) para aprender cómo implementar reglas de validación automática y personalizada.
