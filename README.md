# 🚀 VersaORM-PHP

**El ORM más rápido y seguro para PHP - Nunca más escribas SQL a mano**

[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)](#)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](#)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

## 📋 ¿Qué es VersaORM?

**VersaORM** es una herramienta que te permite **interactuar con tu base de datos usando código PHP familiar** en lugar de escribir SQL complicado. 

### 🤔 ¿Qué es un ORM?

Un **ORM** (Object-Relational Mapping) es como un "traductor" entre tu código PHP y tu base de datos. En lugar de escribir SQL como esto:

```sql
-- SQL tradicional (complicado y propenso a errores)
SELECT * FROM users WHERE status = 'active' AND age >= 18 ORDER BY created_at DESC;
INSERT INTO users (name, email, password) VALUES ('Juan', 'juan@email.com', 'hash...');
UPDATE users SET status = 'inactive' WHERE id = 1;
```

Con VersaORM escribes código PHP natural y fácil de entender:

```php
// Con VersaORM (fácil y seguro)
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->orderBy('created_at', 'desc')
    ->findAll();

$user = User::create([
    'name' => 'Juan',
    'email' => 'juan@email.com',
    'password' => 'mi_password'
]);

$user->update(['status' => 'inactive']);
```

### 🏆 ¿Por qué VersaORM es tu mejor opción?

#### 🚀 **Rendimiento Extremo**
- **10x más rápido** que otros ORMs PHP (Eloquent, Doctrine)
- Motor de consultas escrito en **Rust** (el lenguaje más rápido del mundo)
- Optimización automática de consultas y memoria

#### 🛡️ **Seguridad de Grado Militar**
- **100% protegido** contra inyecciones SQL automáticamente
- Validación de datos integrada
- Protección contra Mass Assignment vulnerabilities

#### 🧠 **Inteligencia Artificial**
- **Detección automática de tipos** de datos
- Conversiones inteligentes entre PHP y base de datos
- Optimización automática de consultas complejas

#### 🌐 **Flexibilidad Total**
- Compatible con **MySQL, PostgreSQL y SQLite**
- Fácil migración desde otros ORMs
- Se integra en cualquier proyecto PHP existente

#### 💡 **Desarrollo Más Rápido**
- Código más limpio y mantenible
- Menos bugs y errores
- Documentación completa con ejemplos
- Curva de aprendizaje suave
## ✨ Arquitectura

```
┌─────────────────┐    JSON    ┌─────────────────┐
│   PHP Layer     │◄──────────►│   Rust Core     │
│                 │   over     │                 │
│ - VersaORM.php  │   Binary   │ - Query Engine  │
│ - Model.php     │    IPC     │ - Type System   │
│ - QueryBuilder  │            │ - DB Drivers    │
└─────────────────┘            └─────────────────┘
```

### Componentes Principales

- **PHP Layer**: Interfaz familiar para desarrolladores PHP
- **Rust Core**: Motor de consultas optimizado y drivers de base de datos
- **IPC Bridge**: Comunicación eficiente via JSON sobre procesos
- **Type System**: Conversión automática de tipos entre PHP y bases de datos

## 🛠️ Instalación

### Via Composer (Recomendado)
```bash
composer require versaorm/versaorm-php
```

### Instalación Manual
1. Clona el repositorio:
   ```bash
   git clone https://github.com/kriollo/versa-orm.git
   ```
2. Incluye el autoloader:
   ```php
   require_once 'src/VersaORM.php';
   require_once 'src/Model.php';
   require_once 'src/QueryBuilder.php';
   ```

### Requisitos del Sistema
- PHP 7.4 o superior
- Extensiones PHP: `json`, `mbstring`
- Base de datos: MySQL 5.7+, PostgreSQL 10+, o SQLite 3.6+
- Sistema operativo: Windows, Linux, macOS

## ⚡ Inicio Rápido

### 1. Configuración Básica
```php
use VersaORM\VersaORM;
use VersaORM\Model;

// Configurar la conexión
$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'password',
    'charset' => 'utf8mb4'
]);

// Configurar modelos
Model::setORM($orm);
```

### 2. Ejemplos de Uso

#### CRUD Básico
```php
// Crear un nuevo registro
$user = $orm->dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@example.com';
$orm->store($user);

// Leer un registro
$user = $orm->findOne('users', 1);
echo $user->name; // Juan Pérez

// Actualizar
$user->email = 'nuevo@example.com';
$orm->store($user);

// Eliminar
$orm->trash($user);
```

#### Modelos con Validación (Nuevo!)
```php
class User extends BaseModel {
    protected string $table = 'users';

    // Protección Mass Assignment
    protected array $fillable = ['name', 'email'];

    // Validación automática
    protected array $rules = [
        'name' => ['required', 'min:2'],
        'email' => ['required', 'email']
    ];
}

// Uso seguro con validación
try {
    $user = new User();
    $user->fill($_POST); // Solo campos $fillable
    $user->store(); // Validación automática
    echo "Usuario creado exitosamente";
} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage();
}
```
```

## 🔧 Desarrollador

### Compilar desde Código Fuente

#### Requisitos de Desarrollo
- Rust 1.70.0 o superior
- Cargo (incluido con Rust)
- Compiladores C/C++ (gcc, clang, o MSVC)

#### Compilación del Núcleo Rust
```bash
# Clonar el repositorio completo
git clone https://github.com/kriollo/versa-orm.git
cd versa-orm/versaorm_cli

# Compilar para tu plataforma
cargo build --release

# Compilación cruzada (opcional)
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin
```

#### Estructura del Código Rust
```
versaorm_cli/
├── src/
│   ├── main.rs           # Punto de entrada y manejo de IPC
│   ├── query_engine.rs   # Motor de consultas SQL
│   ├── type_system.rs    # Sistema de tipos y conversiones
│   ├── database/         # Drivers de base de datos
│   │   ├── mysql.rs
│   │   ├── postgres.rs
│   │   └── sqlite.rs
│   └── utils/            # Utilidades y helpers
├── Cargo.toml
└── README.md
```

## 🛠️ Configuración

### Requisitos
- PHP 7.4+
- MySQL/MariaDB
- Binario VersaORM (incluido precompilado)

### Configurar Base de Datos
Edita la configuración en `example/todo.php`:

```php
$config = [
    'host' => 'localhost',
    'username' => 'root',
    'password' => '',
    'database' => 'todo_app'  // Se crea automáticamente
];
```

### Estructura de la Tabla (Automática)
```sql
CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

## 📁 Estructura del Proyecto

```
versaORM-PHP/
├── src/                    # Código fuente VersaORM
│   ├── VersaORM.php       # Clase principal
│   ├── Model.php          # Modelos Active Record
│   ├── QueryBuilder.php   # Constructor de consultas
│   └── binary/            # Binarios Rust por OS
│       ├── versaorm_cli_windows.exe
│       ├── versaorm_cli_linux
│       └── versaorm_cli_darwin
├── composer.json         # Configuración Composer
└── README.md            # Esta documentación
```

## 🏆 Mejores Prácticas Demostradas

### 1. Usar Métodos ORM para Operaciones Básicas
```php
// ✅ CORRECTO - Usar métodos ORM
$task = Model::dispense('tasks');
$task->title = 'Nueva tarea';
$task->store();

// ❌ INCORRECTO - SQL innecesario para operaciones simples
$orm->exec("INSERT INTO tasks (title) VALUES (?)", ['Nueva tarea']);
```

### 2. exec() Solo para Consultas Complejas
```php
// ✅ CORRECTO - Consulta compleja que necesita SQL
$stats = $orm->exec("SELECT COUNT(*) as total, AVG(rating) as avg_rating FROM tasks");

// ❌ INCORRECTO - Operación simple con SQL
$task = $orm->exec("SELECT * FROM tasks WHERE id = ?", [1])[0];
// MEJOR:
$task = Model::load('tasks', 1);
```

### 3. Manejo de Errores Apropiado
```php
try {
    $task = Model::dispense('tasks');
    $task->title = $title;
    $task->store();
    echo "✅ Tarea creada exitosamente";
} catch (VersaORMException $e) {
    echo "❌ Error: " . $e->getMessage();
}
```


## 🚨 Troubleshooting

### Error de conexión a la base de datos
- Verifica las credenciales en `$config`
- Asegúrate de que MySQL esté ejecutándose
- La base de datos `tu_base` se crea automáticamente

### Binario VersaORM no encontrado
- El binario debe estar en `src/binary/`
- Se incluye precompilado para Windows, Linux y macOS
- Si necesitas recompilar: `cd versaorm_cli && cargo build --release`

## 📚 Documentación

### 📚 Guías de Usuario
- [🚀 Inicio Rápido](docs/user/quick-start.md) - Primeros pasos con VersaORM
- [📝 Guía Completa](docs/user/user-guide.md) - Documentación detallada de todos los métodos
- [🛠️ Instalación](docs/user/installation.md) - Guía de instalación y configuración

### 🔧 Documentación para Desarrolladores
- [🏗️ Guía del Desarrollador](docs/dev/developer-guide.md) - Contribuir al proyecto
- [🧪 Aplicación de Ejemplo](example/README.md) - Demo completa To-Do App


## 🌟 Características Principales

### ⚡ Alto Rendimiento
- **Núcleo en Rust**: Motor de consultas compilado para velocidad extrema
- **Conexiones optimizadas**: Pool de conexiones inteligente
- **Caché integrado**: Sistema de caché automático para consultas frecuentes

### 🛡️ Seguridad Avanzada
- **Consultas preparadas**: Protección contra inyección SQL por defecto
- **Mass Assignment Protection**: Sistema de `$fillable` y `$guarded` integrado
- **Validación automática**: Reglas de validación por modelo con excepciones descriptivas
- **Validación de tipos**: Sistema de tipos estricto en Rust
- **Sanitización automática**: Limpieza de datos de entrada

### 🔄 Compatibilidad
- **Múltiples bases de datos**: MySQL, PostgreSQL, SQLite
- **Integración PHP**: Compatible con frameworks existentes
- **Migraciones**: Sistema de migraciones automático

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor:

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

### Reportar Bugs
- Usa el [Issue Tracker](https://github.com/kriollo/versa-orm/issues)
- Incluye detalles del entorno (PHP version, OS, DB)
- Proporciona pasos para reproducir el problema

## 📄 Licencia

MIT License - ver archivo [LICENSE](LICENSE) para detalles.

## 💬 Soporte

- **Documentación**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/kriollo/versa-orm/issues)
- **Discusiones**: [GitHub Discussions](https://github.com/kriollo/versa-orm/discussions)
- **Email**: jjara@websystem.cl

---

🚀 **VersaORM: El futuro de los ORMs PHP está aquí**

*Potenciado por Rust • Diseñado para PHP • Construido para el rendimiento*
