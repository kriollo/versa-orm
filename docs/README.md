# VersaORM - Documentación Completa

VersaORM es un ORM de alto rendimiento para PHP con núcleo en Rust que combina la flexibilidad de PHP con la velocidad de Rust.

## Características Principales

- 🚀 **Alto Rendimiento**: Núcleo implementado en Rust para máxima velocidad
- 🔄 **API Fluida**: Sintaxis intuitiva tipo Laravel/Eloquent y RedBean-style
- 🎯 **Compatibilidad**: Soporte para múltiples drivers de base de datos
- 🛡️ **Seguridad**: Prepared statements automáticos y validación de entrada
- 🏗️ **Query Builder**: Constructor de consultas flexible y potente
- 📦 **Modelos ActiveRecord**: Patrón ActiveRecord completo
- 🔧 **Trait Helper**: Trait para integración rápida en clases existentes

## Versión

**v1.0.0** - Estable

## Instalación Rápida

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/versaorm-php.git

# Instalar dependencias
composer install

# Compilar el binario de Rust
cd versaorm_cli && cargo build --release
```

## Uso Básico

### Configuración

```php
use VersaORM\VersaORM;

$config = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_bd',
    'username' => 'usuario',
    'password' => 'contraseña'
];

$orm = new VersaORM($config);
```

### Ejemplo Simple

```php
// Crear un nuevo usuario
$user = $orm->dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@ejemplo.com';
$orm->store($user);

// Buscar usuarios
$users = $orm->findAll('users', 'active = ?', [1]);

// Query Builder
$activeUsers = $orm->table('users')
    ->where('active', '=', 1)
    ->where('created_at', '>', '2024-01-01')
    ->orderBy('name', 'asc')
    ->findAll();
```

## Documentación Detallada

### Core Components

- [**VersaORM Class**](api/VersaORM.md) - Clase principal del ORM
- [**Model Class**](api/Model.md) - Modelo ActiveRecord
- [**QueryBuilder Class**](api/QueryBuilder.md) - Constructor de consultas
- [**VersaORMTrait**](api/VersaORMTrait.md) - Trait helper

### Guías

- [**Configuración**](guides/configuration.md) - Configuración detallada
- [**Modelos**](guides/models.md) - Trabajando con modelos
- [**Query Builder**](guides/query-builder.md) - Consultas avanzadas
- [**Consultas SQL Raw**](guides/raw-queries.md) - SQL personalizado
- [**Manejo de Errores**](guides/error-handling.md) - Gestión de errores

### Ejemplos

- [**Ejemplos Básicos**](examples/basic-usage.md) - Operaciones CRUD básicas
- [**Ejemplos Avanzados**](examples/advanced-usage.md) - Casos de uso complejos
- [**Patrones Comunes**](examples/common-patterns.md) - Patrones de diseño

## Arquitectura

```
┌─────────────────┐    JSON     ┌─────────────────┐
│                 │ ────────────>│                 │
│   PHP Layer     │             │   Rust Binary   │
│   (VersaORM)    │ <────────────│  (versaorm_cli) │
│                 │    JSON      │                 │
└─────────────────┘             └─────────────────┘
```

## Licencia

MIT License - Ver archivo LICENSE para más detalles.

## Contribuir

Las contribuciones son bienvenidas. Por favor, lee las guías de contribución antes de enviar un PR.

---

**Desarrollado con ❤️ por el VersaORM Team**
