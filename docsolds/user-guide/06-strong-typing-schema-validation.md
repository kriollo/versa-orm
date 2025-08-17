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

## 🔍 Formas de Declarar Tipos: `propertyTypes()` vs `definePropertyTypes()`

El trait `HasStrongTyping` descubre el mapa de tipos de tu modelo en este orden de prioridad:

1. Método estático público `propertyTypes()` (si existe).
2. Método estático `definePropertyTypes()` (puede ser `protected` o `private`).
3. Si ninguno existe o no devuelve un array válido → no se aplican casts avanzados.

### ¿Por qué dos métodos?

| Método | Visibilidad típica | Caso de uso | Ventaja |
|--------|--------------------|-------------|---------|
| `propertyTypes()` | public static | Quieres exponer la definición a herramientas externas | Inspección directa sin reflexión |
| `definePropertyTypes()` | protected/private static | Prefieres encapsular la definición (API interna) | No “contamina” el API público |

El trait usa reflexión segura para invocar `definePropertyTypes()` incluso si es protegido/privado:

```php
class User extends VersaModel {
    // Opción A (pública)
    public static function propertyTypes(): array {
        return [
            'id' => ['type' => 'int'],
            'uuid' => ['type' => 'uuid'],
            'status' => ['type' => 'enum', 'values' => ['active','inactive']],
        ];
    }
}

class Product extends VersaModel {
    // Opción B (encapsulada)
    protected static function definePropertyTypes(): array {
        return [
            'id' => ['type' => 'int'],
            'price' => ['type' => 'float'],
            'tags' => ['type' => 'set', 'values' => ['new','sale','hot']],
        ];
    }
}
```

### Normalización y Cache
Una vez resuelto el mapa, los tipos (clave `type`) se normalizan a minúsculas y se almacenan en una caché interna por clase, evitando recomputar en cada acceso/cast.

### Qué pasa si no defines ninguno
- El trait devuelve un array vacío → no hay casting especial (los valores pasan “tal cual”).
- Puedes seguir usando `$rules` para validaciones, pero pierdes conversiones automáticas (json → array, set/enum → arrays, uuid validado, etc.).

### Interacción con Validación
- El casting aplica al leer y asignar propiedades antes de que otras validaciones del modelo se disparen.
- Errores de formato (JSON inválido, UUID incorrecto, valor fuera de enum/set) lanzan `VersaORMException` (o `InvalidArgumentException` en casos no críticos) con mensaje contextual.

### Buenas Prácticas
1. Usa `definePropertyTypes()` cuando quieras mantener limpia la superficie pública de la clase.
2. Usa `propertyTypes()` si esperas que tooling externo (generadores, introspectores) lea ese mapa sin reflexión.
3. Declara siempre `uuid`, `enum`, `set`, `json` y campos numéricos críticos para evitar sorpresas de tipo.
4. Mantén sincronizados `values` de enum/set con la base de datos; si cambian, CI debería detectar inconsistencias en validación de esquema.
5. Añade pruebas unitarias para un campo representativo de cada tipo avanzado (json, enum, set, uuid) validando tanto valores válidos como inválidos.

---
## ♻️ Consistencia de Tipos en Todas las Rutas de Lectura

VersaORM garantiza ahora que el casting definido en tu modelo (tipos, enum, set, json, datetime, bool, inet, etc.) se aplica de forma uniforme sin importar cómo recuperes los datos:

| Método | Retorno | Casting aplicado |
|--------|---------|------------------|
| `QueryBuilder->get()` | array<array> | Sí (cada fila se hidrata y se exporta con casting) |
| `QueryBuilder->firstArray()` | array|null | Sí |
| `QueryBuilder->findAll()` | array<Model> | Sí (al acceder / export) |
| `QueryBuilder->findOne()` | Model|null | Sí |
| `VersaModel::getRow()` | array|null | Sí (post-proceso) |
| `VersaModel::getCell()` | mixed | Sí (si el campo está tipado) |
| `Model->export()` | array | Sí (ahora fuerza accessor/cast por atributo) |

Incluso el camino de hidratación optimizado (fast-path) ejecuta la fase de export con casting para asegurar que flags booleanos, fechas y colecciones mantengan consistencia. Si agregas nuevos tipos soportados en `HasStrongTyping`, heredarás esta consistencia automáticamente.

Recomendación: define siempre tus tipos críticos (uuid, bool, enum, set, json, datetime, inet) para evitar depender de valores crudos de PDO y asegurar serialización JSON estable.

---
