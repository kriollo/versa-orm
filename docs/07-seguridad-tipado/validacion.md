# Validación en VersaORM

VersaORM proporciona un sistema robusto de validación que te permite definir reglas automáticas y personalizadas mediante `$rules`, tipado fuerte con `definePropertyTypes()`, y el método `validate()` para garantizar la integridad de los datos antes de guardar.

## ¿Qué es la Validación?

La validación es el proceso de verificar que los datos cumplan con ciertas reglas antes de ser almacenados. VersaORM ofrece:

- **Validación Automática**: Basada en tipos de datos y restricciones de base de datos (usando `definePropertyTypes()` y el esquema)
- **Validación Personalizada**: Reglas específicas definidas por el desarrollador en `$rules`
- **Validación en Tiempo Real**: Se ejecuta llamando a `$model->validate()` antes de guardar
- **Mensajes de Error Descriptivos**: El array devuelto por `validate()` contiene los mensajes

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

$user->age = 'veinticinco';  // ❌ String en campo integer
$errors = $user->validate();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
    // Error: El campo 'age' debe ser un número entero
}
```

### Validación de Longitud

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    protected static $rules = [
        'name' => ['min:2', 'max:100'],
        'email' => ['max:255'],
        'phone' => ['max:20'],
        'password' => ['min:8'],
    ];
}

$user = new UserModel();
$user->name = 'A';  // ❌ Muy corto (mínimo 2 caracteres)
$user->email = str_repeat('a', 300); // ❌ Muy largo (máximo 255)
$errors = $user->validate();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
    // El campo 'name' debe tener al menos 2 caracteres
}
```

## Validación Personalizada

### Reglas Básicas en el Modelo

```php
class ProductModel extends VersaModel {
    protected static $table = 'products';

    protected static $rules = [
        'name' => ['required', 'min:3', 'max:100'],
        'price' => ['required', 'numeric', 'min:0.01'],
        'category_id' => ['required'],
        'email' => ['email'],
        'website' => ['url'],
    ];
}
```

### Uso de Validación con Reglas

```php
$product = new ProductModel();
$product->name = 'TV';           // ❌ Muy corto
$product->price = -100;          // ❌ Precio negativo
$product->email = 'no-es-email'; // ❌ Email inválido
$errors = $product->validate();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
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
    'name' => ['required'],
    'age' => ['numeric'],
    'price' => ['numeric'],
    'active' => ['boolean'],
    'email' => ['email'],
    'website' => ['url'],
    'password' => ['min:8', 'max:50'],
    'description' => ['max:500'],
    // Puedes extender validateSingleRule para agregar más reglas
];
```

### Reglas de Relación

Puedes implementar validaciones de relación extendiendo el método de validación en tu modelo, por ejemplo consultando la existencia de una relación antes de guardar.

## Validación Personalizada Avanzada

### Métodos de Validación Personalizados

Puedes agregar métodos propios en el modelo y llamarlos desde tu lógica antes de guardar, o extender `validateSingleRule` para reglas avanzadas.

### Validadores Personalizados

Puedes implementar validadores personalizados extendiendo el método `validateSingleRule` en tu modelo y llamando funciones propias. Por ejemplo:

```php
class CompanyModel extends VersaModel {
    protected static $rules = [
        'phone' => ['required', 'mexican_phone'],
        'rfc' => ['required', 'rfc'],
        'meeting_date' => ['workday'],
    ];

    protected function validateSingleRule($field, $rule, $value) {
        if ($rule === 'mexican_phone') {
            return preg_match('/^(\+52|52)?[1-9]\d{9}$/', $value);
        }
        if ($rule === 'rfc') {
            $pattern = '/^[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}$/';
            return preg_match($pattern, strtoupper($value));
        }
        if ($rule === 'workday') {
            $date = new DateTime($value);
            $dayOfWeek = $date->format('N');
            return $dayOfWeek >= 1 && $dayOfWeek <= 5;
        }
        return parent::validateSingleRule($field, $rule, $value);
    }
}
```

### Ejemplo de regla personalizada: Validación de RUT chileno

Puedes crear reglas personalizadas para validar formatos específicos, como el RUT chileno. Solo necesitas extender el método `validateSingleRule` en tu modelo:

```php
class UserModel extends VersaModel {
    protected static $rules = [
        'rut' => ['required', 'rut_chile'],
        'name' => ['required'],
    ];

    protected function validateSingleRule($field, $rule, $value) {
        if ($rule === 'rut_chile') {
            // Validación básica de RUT chileno (sin puntos, con guion)
            if (!preg_match('/^\d{7,8}-[\dkK]$/', $value)) {
                return false;
            }
            // Validación de dígito verificador
            $parts = explode('-', $value);
            $number = $parts[0];
            $dv = strtoupper($parts[1]);
            $sum = 0;
            $factor = 2;
            for ($i = strlen($number) - 1; $i >= 0; $i--) {
                $sum += $number[$i] * $factor;
                $factor = $factor == 7 ? 2 : $factor + 1;
            }
            $expected = 11 - ($sum % 11);
            $expectedDV = $expected == 11 ? '0' : ($expected == 10 ? 'K' : (string)$expected);
            return $dv === $expectedDV;
        }
        return parent::validateSingleRule($field, $rule, $value);
    }
}
```

**Uso:**

```php
$user = new UserModel();
$user->rut = '12345678-5'; // RUT válido
$user->name = 'Juan';
$errors = $user->validate();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
}
```

Si el RUT es inválido, el sistema devolverá un mensaje de error. Puedes personalizar el mensaje agregando lógica en el método o extendiendo la función de mensajes.

Este patrón te permite validar cualquier formato nacional o empresarial que necesites, manteniendo la lógica centralizada y reutilizable.

## Validación Condicional

### Validación Basada en Condiciones

Puedes condicionar la validación según el estado del modelo, el contexto o cualquier lógica de negocio, extendiendo el método de validación o agregando helpers. Por ejemplo:

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    protected function validateCustomRules() {
        $errors = [];
        if ($this->active && empty($this->email)) {
            $errors[] = 'Los usuarios activos deben tener email';
        }
        if ($this->isNew() && empty($this->password)) {
            $errors[] = 'La contraseña es requerida para nuevos usuarios';
        }
        if ($this->type === 'admin' && !in_array($this->role, ['super_admin', 'admin'])) {
            $errors[] = 'Rol inválido para usuario administrador';
        }
        return $errors;
    }
}
```

### Validación por Grupos

A veces necesitas validar los datos de manera diferente según el contexto (por ejemplo, al guardar un borrador, publicar, o archivar). Puedes crear métodos específicos para cada grupo y llamarlos según el caso:

```php
class EventModel extends VersaModel {
    protected static $rules = [
        'name' => ['required'],
        'date' => ['required'],
    ];

    public function validate($context = 'default') {
        $errors = $this->validate(); // validación estándar
        if ($context === 'publish') {
            if (empty($this->location)) {
                $errors[] = 'La ubicación es obligatoria para publicar.';
            }
        }
        if ($context === 'archive') {
            if ($this->date > date('Y-m-d')) {
                $errors[] = 'No puedes archivar eventos futuros.';
            }
        }
        return $errors;
    }
}
```

**Uso:**

```php
$event = new EventModel();
$event->name = 'Conferencia';
$event->date = '2025-09-01';
$event->location = '';
$errors = $event->validate('publish');
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
    // Resultado: La ubicación es obligatoria para publicar.
}
```

---

## Validación de Arrays y JSON

En muchos casos, los modelos tienen propiedades que son arrays o JSON (por ejemplo, una lista de productos en una orden). Puedes validar la estructura y los valores de estos elementos extendiendo el método de validación:

```php
class OrderModel extends VersaModel {
    protected static $rules = [
        'items' => ['required'],
    ];

    protected function validateCustomRules() {
        $errors = [];
        if (!is_array($this->items) || empty($this->items)) {
            $errors[] = 'La orden debe tener al menos un producto.';
        } else {
            foreach ($this->items as $i => $item) {
                if (empty($item['product_id'])) {
                    $errors[] = "El producto en la posición $i no tiene ID.";
                }
                if (empty($item['quantity']) || $item['quantity'] <= 0) {
                    $errors[] = "Cantidad inválida en el producto $i.";
                }
            }
        }
        return $errors;
    }
}
```

**Uso:**

```php
$order = new OrderModel();
$order->items = [
    ['product_id' => 1, 'quantity' => 2],
    ['product_id' => '', 'quantity' => 0], // errores
];
$errors = $order->validateCustomRules();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
    // Resultado:
    // El producto en la posición 1 no tiene ID.
    // Cantidad inválida en el producto 1.
}
```

---

### Validar Elementos de Array

Puedes recorrer los elementos de un array y agregar errores personalizados según la lógica de tu aplicación. Este patrón es útil para validar listas de objetos, configuraciones, o cualquier estructura compleja:

```php
class ConfigModel extends VersaModel {
    protected static $rules = [
        'settings' => ['required'],
    ];

    protected function validateCustomRules() {
        $errors = [];
        $required = ['theme', 'language', 'timezone'];
        if (!is_array($this->settings)) {
            $errors[] = 'La configuración debe ser un array.';
        } else {
            foreach ($required as $key) {
                if (!isset($this->settings[$key])) {
                    $errors[] = "Falta configuración requerida: $key";
                }
            }
            $validThemes = ['light', 'dark', 'auto'];
            if (isset($this->settings['theme']) && !in_array($this->settings['theme'], $validThemes)) {
                $errors[] = 'Tema inválido.';
            }
        }
        return $errors;
    }
}
```

**Uso:**

```php
$config = new ConfigModel();
$config->settings = [
    'theme' => 'neon', // inválido
    'language' => 'es',
    // falta timezone
];
$errors = $config->validateCustomRules();
if ($errors) {
    foreach ($errors as $msg) {
        echo $msg . "\n";
    }
    // Resultado:
    // Falta configuración requerida: timezone
    // Tema inválido.
}
```

---

## Diferencia y uso de validateSingleRule vs validateCustomRules

En VersaORM puedes personalizar la validación de dos formas complementarias:

### 1. `validateSingleRule($field, $rule, $value)`

- Se usa para definir cómo se valida una regla específica para un campo.
- El sistema lo llama automáticamente para cada regla definida en `$rules`.
- Ideal para agregar reglas personalizadas por campo (ejemplo: RUT chileno, teléfono, etc).

**Ejemplo:**

```php
class UserModel extends VersaModel {
    protected static $rules = [
        'rut' => ['required', 'rut_chile'],
        'email' => ['required', 'email'],
    ];

    protected function validateSingleRule($field, $rule, $value) {
        if ($rule === 'rut_chile') {
            // ...validación de RUT...
        }
        return parent::validateSingleRule($field, $rule, $value);
    }
}
```

### 2. `validateCustomRules()`

- Se usa para agregar validaciones complejas, condicionales o de estructura (arrays, relaciones, lógica de negocio).
- Debe devolver un array de errores adicionales.
- No depende de un solo campo, sino de la lógica global del modelo.

**Ejemplo:**

```php
class OrderModel extends VersaModel {
    protected static $rules = [
        'items' => ['required'],
    ];

    protected function validateCustomRules() {
        $errors = [];
        if (!is_array($this->items) || empty($this->items)) {
            $errors[] = 'La orden debe tener al menos un producto.';
        }
        // ...más lógica...
        return $errors;
    }
}
```

### ¿Cómo se combinan?

Cuando llamas a `$model->validate()`, VersaORM:
- Valida cada campo usando las reglas de `$rules` y llama a `validateSingleRule` si existe una regla personalizada.
- Después, si existe el método `validateCustomRules`, lo ejecuta y agrega los errores devueltos.

**Ejemplo combinado:**

```php
class UserModel extends VersaModel {
    protected static $rules = [
        'rut' => ['required', 'rut_chile'],
        'email' => ['required', 'email'],
    ];

    protected function validateSingleRule($field, $rule, $value) {
        if ($rule === 'rut_chile') {
            // ...validación de RUT...
        }
        return parent::validateSingleRule($field, $rule, $value);
    }

    protected function validateCustomRules() {
        $errors = [];
        if ($this->email && !str_ends_with($this->email, '@empresa.cl')) {
            $errors[] = 'El email debe ser corporativo (@empresa.cl).';
        }
        return $errors;
    }
}
```

**Resumen:**
- Usa `validateSingleRule` para reglas personalizadas por campo.
- Usa `validateCustomRules` para validaciones globales, condicionales o de estructura.
- Ambos métodos pueden convivir y se ejecutan automáticamente al llamar a `$model->validate()`.

Esto te permite crear validaciones flexibles y robustas, incluso si nunca has usado un ORM antes.
La validación en VersaORM te ayuda a mantener la integridad de los datos y proporcionar una mejor experiencia al usuario con mensajes de error claros y específicos.

## Siguiente Paso

Continúa con [Protección Mass Assignment](mass-assignment.md) para aprender cómo proteger tu aplicación contra asignación masiva no autorizada.
