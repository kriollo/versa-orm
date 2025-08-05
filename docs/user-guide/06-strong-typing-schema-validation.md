# 🎯 Tipado Fuerte y Validación de Esquemas

Esta sección proporciona detalles sobre el **sistema de tipado fuerte** y la **validación de esquemas** en VersaORM, diseñado para asegurar la consistencia y la integridad de los datos entre el modelo PHP y la base de datos.

## 🔄 Antes vs Después

### ❌ ANTES (PHP tradicional - propenso a errores)
```php
// Sin tipado - cualquier cosa puede pasar
class User {
    public $id;       // ¿int? ¿string? ¿null?
    public $name;     // ¿qué pasa si es muy largo?
    public $email;    // ¿es válido el formato?
    public $settings; // ¿array? ¿JSON? ¿string?
    public $active;   // ¿bool? ¿int? ¿string?
}

// Problemas comunes:
$user->id = "abc";           // Error silencioso
$user->name = str_repeat('a', 1000); // Excede límite DB
$user->settings = "invalid json";    // Falla al guardar
$user->active = "maybe";             // ¿true o false?
```

### ✅ DESPUÉS (VersaORM - tipado fuerte y seguro)
```php
class User extends VersaModel {
    protected static function definePropertyTypes(): array {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
            'email' => ['type' => 'string', 'max_length' => 255, 'unique' => true],
            'settings' => ['type' => 'json', 'nullable' => true],
            'active' => ['type' => 'bool', 'nullable' => false, 'default' => true],
            'uuid' => ['type' => 'uuid', 'nullable' => false],
            'status' => ['type' => 'enum', 'values' => ['active', 'inactive', 'pending']],
            'tags' => ['type' => 'set', 'values' => ['work', 'personal', 'urgent']],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}

// Automáticamente seguro y validado:
$user = new User();
$user->id = "123";        // Se convierte automáticamente a int(123)
$user->name = "Juan";     // Validado: longitud OK
$user->settings = ['theme' => 'dark']; // Se convierte a JSON automáticamente
$user->active = "1";      // Se convierte a bool(true)
```

## 🏗️ Definición de Tipos en Modelos

### Tipos Básicos

#### Números
```php
protected static function definePropertyTypes(): array {
    return [
        'id' => ['type' => 'int', 'nullable' => false],
        'age' => ['type' => 'int', 'nullable' => true],
        'price' => ['type' => 'float', 'nullable' => false],
        'rating' => ['type' => 'decimal', 'precision' => 2],
    ];
}

// Uso automático:
$product->price = "19.99";  // Se convierte a float(19.99)
$product->rating = 4.5;     // Mantiene precisión decimal
```

#### Texto
```php
protected static function definePropertyTypes(): array {
    return [
        'name' => ['type' => 'string', 'max_length' => 255, 'nullable' => false],
        'description' => ['type' => 'string', 'max_length' => 1000, 'nullable' => true],
        'content' => ['type' => 'text', 'nullable' => true], // Sin límite
    ];
}

// Validación automática:
$post->name = str_repeat('a', 300); // ❌ Error: excede max_length
$post->description = "Texto válido";  // ✅ OK
```

#### Booleanos
```php
protected static function definePropertyTypes(): array {
    return [
        'active' => ['type' => 'bool', 'nullable' => false, 'default' => true],
        'verified' => ['type' => 'boolean', 'nullable' => true],
    ];
}

// Conversiones inteligentes:
$user->active = "1";      // → bool(true)
$user->active = "true";   // → bool(true)
$user->active = "yes";    // → bool(true)
$user->active = "on";     // → bool(true)
$user->active = "0";      // → bool(false)
$user->active = "false";  // → bool(false)
```

### Tipos Avanzados

#### JSON
```php
protected static function definePropertyTypes(): array {
    return [
        'settings' => ['type' => 'json', 'nullable' => true],
        'metadata' => ['type' => 'json', 'nullable' => false, 'default' => '{}'],
    ];
}

// Conversión automática:
$user->settings = ['theme' => 'dark', 'lang' => 'es'];
// Se guarda como: {"theme":"dark","lang":"es"}

// Al leer:
$theme = $user->settings['theme']; // "dark" (array PHP automático)
```

#### UUID
```php
protected static function definePropertyTypes(): array {
    return [
        'uuid' => ['type' => 'uuid', 'nullable' => false],
        'external_id' => ['type' => 'uuid', 'nullable' => true],
    ];
}

// Validación automática:
$user->uuid = '550e8400-e29b-41d4-a716-446655440000'; // ✅ OK
$user->uuid = 'invalid-uuid'; // ❌ Error: formato UUID inválido
```

#### Enumeraciones
```php
protected static function definePropertyTypes(): array {
    return [
        'status' => [
            'type' => 'enum', 
            'values' => ['draft', 'published', 'archived'],
            'default' => 'draft'
        ],
        'priority' => [
            'type' => 'enum',
            'values' => ['low', 'medium', 'high', 'critical']
        ],
    ];
}

// Validación estricta:
$post->status = 'published'; // ✅ OK
$post->status = 'invalid';   // ❌ Error: valor no permitido
```

#### Conjuntos (SET)
```php
protected static function definePropertyTypes(): array {
    return [
        'tags' => [
            'type' => 'set',
            'values' => ['work', 'personal', 'urgent', 'important']
        ],
        'permissions' => [
            'type' => 'set',
            'values' => ['read', 'write', 'delete', 'admin']
        ],
    ];
}

// Múltiples valores:
$task->tags = ['work', 'urgent'];           // ✅ OK
$task->tags = 'work,personal';              // ✅ OK (string separado por comas)
$task->tags = '["work", "important"]';     // ✅ OK (JSON array)
$task->tags = ['invalid'];                 // ❌ Error: valor no permitido
```

#### Fechas y Tiempo
```php
protected static function definePropertyTypes(): array {
    return [
        'created_at' => ['type' => 'datetime', 'nullable' => false],
        'updated_at' => ['type' => 'datetime', 'nullable' => true],
        'published_date' => ['type' => 'date', 'nullable' => true],
        'login_time' => ['type' => 'timestamp', 'nullable' => true],
    ];
}

// Conversiones automáticas:
$post->created_at = '2023-01-01 12:00:00';    // → DateTime object
$post->created_at = time();                   // → DateTime object
$post->created_at = new DateTime();           // → DateTime object
```

#### Direcciones IP (INET)
```php
protected static function definePropertyTypes(): array {
    return [
        'ip_address' => ['type' => 'inet', 'nullable' => true],
        'last_login_ip' => ['type' => 'inet', 'nullable' => true],
    ];
}

// Validación de IP:
$session->ip_address = '192.168.1.1';     // ✅ OK (IPv4)
$session->ip_address = '::1';             // ✅ OK (IPv6)
$session->ip_address = 'invalid-ip';      // ❌ Error: IP inválida
```

## Validación de Esquemas

La validación de esquemas asegura que la estructura de los modelos en PHP sea consistente con el esquema de base de datos subyacente.

### Ejecución de la Validación

```php
$model = new User();
$errors = $model->validateSchemaConsistency();
if (!empty($errors)) {
    // Manejar inconsistencias
    print_r($errors);
}
```

### Qué se Valida

- **Compatibilidad de Tipos**: Verifica que el tipo del modelo sea compatible con el tipo de columna de la base de datos.
- **Nullabilidad**: Compara la capacidad de las columnas para aceptar valores nulos.
- **Longitud de cadenas**: Valida que la longitud máxima no excede la permitida.
- **Consistencia de Enumeraciones**: Asegura que los valores `enum` y `set` estén definidos correctamente.

### Informes de Error

Cualquier discrepancia resultará en un error detallado que incluye el tipo de fallo y la acción recomendada para solucionarlo.

