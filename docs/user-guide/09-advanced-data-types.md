# Tipos de Datos Avanzados en VersaORM

VersaORM proporciona un sistema completo de manejo de tipos de datos avanzados que funciona de manera consistente entre MySQL, PostgreSQL y SQLite. Este documento describe todos los tipos soportados y cómo utilizarlos.

## 🎯 Tipos Básicos Universales

### Tipos Primitivos
```php
// Definición en el modelo
public static function getPropertyTypes(): array
{
    return [
        'id' => ['type' => 'int', 'primary' => true, 'auto_increment' => true],
        'name' => ['type' => 'string', 'max_length' => 255],
        'price' => ['type' => 'float', 'precision' => 10, 'scale' => 2],
        'active' => ['type' => 'boolean', 'default' => true],
        'description' => ['type' => 'text', 'nullable' => true],
    ];
}
```

| Tipo | PHP | MySQL | PostgreSQL | SQLite | Descripción |
|------|-----|-------|------------|--------|-------------|
| `int` | `int` | `INT`, `BIGINT` | `INTEGER`, `BIGINT` | `INTEGER` | Números enteros |
| `float` | `float` | `FLOAT`, `DOUBLE` | `REAL`, `DOUBLE PRECISION` | `REAL` | Números decimales |
| `string` | `string` | `VARCHAR`, `CHAR` | `VARCHAR`, `CHAR` | `TEXT` | Cadenas de texto |
| `text` | `string` | `TEXT`, `LONGTEXT` | `TEXT` | `TEXT` | Texto largo |
| `boolean` | `bool` | `TINYINT(1)` | `BOOLEAN` | `INTEGER` | Verdadero/Falso |

## 🚀 Tipos Avanzados

### 1. JSON - Datos Estructurados
```php
// Definición
'metadata' => [
    'type' => 'json',
    'nullable' => true,
    'default' => '{}',
],

// Uso
$product = VersaModel::dispense('products');
$product->metadata = ['color' => 'red', 'size' => 'large'];
$product->store();

// Automáticamente convertido a JSON en base de datos
// y a array en PHP
```

**Soporte por Base de Datos:**
- **MySQL 5.7+**: Tipo `JSON` nativo con validación
- **PostgreSQL**: Tipos `JSON` y `JSONB` con indexación
- **SQLite**: Almacenado como `TEXT`, validado por VersaORM

### 2. UUID - Identificadores Únicos
```php
// Definición
'uuid' => [
    'type' => 'uuid',
    'unique' => true,
    'required' => true,
],

// Uso
$user = VersaModel::dispense('users');
$user->uuid = '550e8400-e29b-41d4-a716-446655440000';
$user->store();

// Validación automática de formato RFC 4122
```

**Soporte por Base de Datos:**
- **MySQL**: `CHAR(36)` con validación de formato
- **PostgreSQL**: Tipo `UUID` nativo con extensión uuid-ossp
- **SQLite**: `TEXT` con validación de formato

### 3. ENUM - Valores Enumerados
```php
// Definición
'status' => [
    'type' => 'enum',
    'options' => ['draft', 'published', 'archived'],
    'default' => 'draft',
],

// Uso
$post = VersaModel::dispense('posts');
$post->status = 'published'; // Validado automáticamente
$post->store();
```

**Soporte por Base de Datos:**
- **MySQL**: Tipo `ENUM` nativo
- **PostgreSQL**: Tipos ENUM personalizados o CHECK constraints
- **SQLite**: CHECK constraints con validación

### 4. SET - Conjuntos de Valores
```php
// Definición
'tags' => [
    'type' => 'set',
    'options' => ['tech', 'news', 'tutorial', 'review'],
    'nullable' => true,
],

// Uso
$article = VersaModel::dispense('articles');
$article->tags = ['tech', 'tutorial']; // Array en PHP
$article->store(); // 'tech,tutorial' en MySQL
```

**Soporte por Base de Datos:**
- **MySQL**: Tipo `SET` nativo
- **PostgreSQL**: Array de texto con validación
- **SQLite**: Texto separado por comas con validación

### 5. INET - Direcciones de Red (PostgreSQL)
```php
// Definición
'ip_address' => [
    'type' => 'inet',
    'nullable' => true,
],

// Uso
$connection = VersaModel::dispense('connections');
$connection->ip_address = '192.168.1.1';
$connection->network = '192.168.1.0/24'; // CIDR
$connection->store();
```

**Soporte por Base de Datos:**
- **PostgreSQL**: Tipos `INET`, `CIDR`, `MACADDR` nativos
- **MySQL**: `VARCHAR` con validación de formato IP
- **SQLite**: `TEXT` con validación de formato IP

### 6. BLOB - Datos Binarios
```php
// Definición
'image_data' => [
    'type' => 'blob',
    'encoding' => 'base64',
    'nullable' => true,
],

// Uso
$file = VersaModel::dispense('files');
$binaryData = file_get_contents('image.jpg');
$file->image_data = base64_encode($binaryData);
$file->store();

// Recuperación
$decoded = base64_decode($file->image_data);
```

### 7. Arrays PostgreSQL
```php
// Definición
'categories' => [
    'type' => 'array',
    'array_type' => 'text[]', // PostgreSQL específico
    'nullable' => true,
],

// Uso
$product = VersaModel::dispense('products');
$product->categories = ['electronics', 'computers', 'laptops'];
$product->store();
```

## 🔧 Configuración de Mapeos Personalizados

### Archivo de Configuración
```json
// config/type_mappings.json
{
  "type_mappings": [
    {
      "from": "json",
      "to": "array",
      "description": "Convert JSON strings to PHP arrays"
    },
    {
      "from": "custom_type",
      "to": "string",
      "custom_cast": "my_custom_function"
    }
  ],
  "database_specific": {
    "mysql": {
      "geometry": "string",
      "point": "array"
    },
    "postgresql": {
      "jsonb": "array",
      "tsvector": "string"
    }
  }
}
```

### Carga de Configuración
```php
// En tu aplicación
$orm = new VersaORM($config);
$orm->loadTypeMappings('config/type_mappings.json');
```

## 📝 Definición de Tipos en Modelos

### Modelo Completo con Tipos Avanzados
```php
<?php

use VersaORM\VersaModel;
use VersaORM\Traits\HasStrongTyping;
use VersaORM\Interfaces\TypedModelInterface;

class Product extends VersaModel implements TypedModelInterface
{
    use HasStrongTyping;

    protected string $table = 'products';

    public static function getPropertyTypes(): array
    {
        return [
            'id' => [
                'type' => 'int',
                'primary' => true,
                'auto_increment' => true,
            ],
            'uuid' => [
                'type' => 'uuid',
                'unique' => true,
                'required' => true,
            ],
            'name' => [
                'type' => 'string',
                'max_length' => 255,
                'required' => true,
            ],
            'price' => [
                'type' => 'decimal',
                'precision' => 10,
                'scale' => 2,
                'required' => true,
            ],
            'metadata' => [
                'type' => 'json',
                'nullable' => true,
                'default' => '{}',
            ],
            'tags' => [
                'type' => 'set',
                'options' => ['electronics', 'clothing', 'books'],
                'nullable' => true,
            ],
            'status' => [
                'type' => 'enum',
                'options' => ['draft', 'published', 'archived'],
                'default' => 'draft',
            ],
            'image_data' => [
                'type' => 'blob',
                'encoding' => 'base64',
                'nullable' => true,
            ],
            'created_at' => [
                'type' => 'datetime',
                'auto_timestamp' => true,
            ],
        ];
    }

    // Mutadores personalizados
    public function getMutators(): array
    {
        return [
            'price' => fn($value) => number_format((float)$value, 2, '.', ''),
            'name' => fn($value) => ucfirst(trim($value)),
        ];
    }

    // Accesorios personalizados
    public function getAccessors(): array
    {
        return [
            'formatted_price' => fn() => '$' . number_format($this->price, 2),
            'is_published' => fn() => $this->status === 'published',
        ];
    }
}
```

## 🔍 Validación y Consistencia

### Validación Automática de Esquema
```php
// Verificar consistencia entre modelo y base de datos
$product = new Product();
$errors = $product->validateSchemaConsistency();

if (!empty($errors)) {
    foreach ($errors as $error) {
        echo "⚠️ {$error}\n";
    }
}
```

### Advertencias en Consola
VersaORM automáticamente muestra advertencias si detecta inconsistencias:

```bash
⚠️  ADVERTENCIA: La propiedad 'extra_field' no existe en la base de datos
⚠️  INCONSISTENCIA: 'price' - DB: decimal(10,2) vs Modelo: float
💡 INFO: Columna 'legacy_field' existe en DB pero no está definida en el modelo
```

## 🚦 Casting Bidireccional

### PHP → Base de Datos
```php
// Automático al guardar
$product->metadata = ['color' => 'red']; // Array PHP
$product->store(); // Se convierte a JSON string

// Manual
$jsonString = $product->castToDatabaseType('metadata', ['color' => 'red']);
// Resultado: '{"color":"red"}'
```

### Base de Datos → PHP
```php
// Automático al cargar
$product = Product::find(1);
$metadata = $product->metadata; // Automáticamente array PHP

// Manual
$array = $product->castToPhpType('metadata', '{"color":"red"}');
// Resultado: ['color' => 'red']
```

## 🎯 Mejores Prácticas

### 1. Uso de Interfaces
```php
class MyModel extends VersaModel implements TypedModelInterface
{
    use HasStrongTyping;

    // Siempre implementar getPropertyTypes()
    public static function getPropertyTypes(): array { ... }
}
```

### 2. Validación Proactiva
```php
// En tu aplicación, verificar esquemas regularmente
foreach ($models as $modelClass) {
    $model = new $modelClass();
    $errors = $model->validateSchemaConsistency();

    if (!empty($errors)) {
        $this->logger->warning("Inconsistencias en {$modelClass}", $errors);
    }
}
```

### 3. Configuración por Entorno
```php
// Desarrollo: mostrar todas las advertencias
if (getenv('APP_ENV') === 'development') {
    $orm->setOption('show_type_warnings', true);
}

// Producción: solo logging
if (getenv('APP_ENV') === 'production') {
    $orm->setOption('log_type_inconsistencies', true);
}
```

## 📊 Rendimiento

### Optimizaciones Automáticas
- **Caché de metadatos**: Los tipos se cachean automáticamente
- **Casting lazy**: Solo se convierten tipos cuando es necesario
- **Validación eficiente**: Regex compiladas y optimizadas

### Benchmarks Típicos
- **JSON casting**: ~0.001ms para objetos pequeños
- **UUID validation**: ~0.0001ms por validación
- **Array processing**: ~0.01ms para arrays de 1000 elementos

## 🔧 Extensibilidad

### Tipos Personalizados
```php
// Registrar un tipo personalizado
$orm->registerCustomType('coordinate', [
    'cast_to_php' => function($value) {
        [$lat, $lng] = explode(',', $value);
        return ['lat' => (float)$lat, 'lng' => (float)$lng];
    },
    'cast_to_db' => function($value) {
        return $value['lat'] . ',' . $value['lng'];
    },
    'validate' => function($value) {
        return isset($value['lat']) && isset($value['lng']);
    }
]);
```

## 🆘 Solución de Problemas

### Errores Comunes
1. **"Invalid JSON for property"**: Verificar formato JSON válido
2. **"Invalid UUID format"**: Usar formato RFC 4122 (8-4-4-4-12)
3. **"Type mismatch"**: Verificar consistencia entre modelo y DB

### Debug
```php
// Activar debug detallado
$orm->setDebug(true);

// Ver casting en tiempo real
$orm->setOption('log_type_casting', true);
```

---

Este sistema de tipos convierte a VersaORM en uno de los ORMs más potentes y flexibles para PHP, proporcionando seguridad de tipos sin sacrificar rendimiento.
