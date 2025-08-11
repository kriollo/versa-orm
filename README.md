# 🚀 VersaORM-PHP (Modo PHP / PDO)

**ORM sencillo y seguro para PHP – minimiza SQL manual y acelera tu desarrollo.**

[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)](#)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

> Esta documentación está enfocada al **modo PHP puro (PDO)**. El núcleo nativo (binario) se encuentra en revisión y se re‑integrará más adelante. Nada de lo aquí descrito requiere compilar nada: solo PHP + tu base de datos.

- 📚 Documentación: [docs/README.md](docs/README.md)
- 🧭 Primeros pasos: [docs/getting-started/README.md](docs/getting-started/README.md)
- 📘 Guía de uso (básico → avanzado): [docs/user-guide/README.md](docs/user-guide/README.md)
- 🤝 Contribuir: [docs/contributor-guide/README.md](docs/contributor-guide/README.md)

## 📋 ¿Qué es VersaORM?

VersaORM te permite interactuar con tu base de datos usando **objetos PHP** y un **Query Builder fluido**, apoyándose internamente en **PDO**. Así reduces errores, previenes inyecciones SQL y escribes código expresivo.

### 🤔 ¿Qué es un ORM?

Un **ORM** (Object-Relational Mapping) traduce tus objetos PHP a filas en la base de datos. En vez de escribir SQL como esto:

```sql
-- SQL tradicional (complicado y propenso a errores)
SELECT * FROM users WHERE status = 'active' AND age >= 18 ORDER BY created_at DESC;
INSERT INTO users (name, email, password) VALUES ('Juan', 'juan@email.com', 'hash...');
UPDATE users SET status = 'inactive' WHERE id = 1;
```

Con VersaORM escribes código PHP natural y seguro:

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

// 🆕 Con Modo Lazy (optimización automática para consultas complejas)
$users = $orm->table('users')
    ->lazy()                           // 🚀 Activa optimización automática
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->orderBy('created_at', 'desc')
    ->collect();                       // ✅ Ejecuta consulta optimizada
```

### 🏆 ¿Por qué elegir VersaORM (Modo PDO)?

| Necesidad | Sin ORM (solo PDO) | Con VersaORM |
|-----------|--------------------|--------------|
| Seguridad | Debes escribir y parametrizar cada sentencia | Parámetros preparados siempre |
| Mantenimiento | SQL repetido en muchos archivos | Lógica centralizada y fluida |
| Curva de aprendizaje | Conocer bien SQL + PDO | API consistente (where, join, order, etc.) |
| Refactors | Buscar/editar cadenas SQL | Cambias métodos encadenados |
| Errores típicos | Inyección, comas, orden de placeholders | Minimizado por API tipada básica |

### Características Clave (Modo PHP)

- ✅ Construido sobre PDO (sin dependencias complicadas)
- 🛡️ Protección por defecto contra inyección SQL (prepared statements internos)
- 🧩 Modelos Active Record sencillos (`dispense`, `load`, `store`, `trash`)
- 🔍 Query Builder fluido (`where`, `join`, `groupBy`, `having`, `orderBy`, `limit`)
- � Relaciones básicas implementables con métodos de conveniencia
- 💾 Conversión de tipos común (fechas, booleanos) y helpers
- 🚫 Cero necesidad de compilar binarios

> Cuando el núcleo nativo vuelva a estar disponible podrás activar rendimiento adicional sin cambiar tu código de aplicación.

## ✨ Arquitectura (Modo PHP)

```
┌──────────────────────────┐
│        Tu Código         │
│  (Modelos + Consultas)   │
└────────────┬────────────┘
             │ API PHP
┌────────────▼────────────┐
│       VersaORM PHP       │
│ - VersaORM.php           │
│ - VersaModel.php         │
│ - QueryBuilder.php       │
└────────────┬────────────┘
             │ PDO
┌────────────▼────────────┐
│     Base de Datos        │
└──────────────────────────┘
```

Sin procesos externos; todo fluye a través de PDO.

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

### 2. Ejemplos de Uso (Side‑by‑Side SQL vs ORM)

#### CRUD Básico con ORM vs SQL Manual
```php
// SQL Manual (PDO)
$stmt = $pdo->prepare("INSERT INTO users (name,email) VALUES (?,?)");
$stmt->execute(['Juan Pérez','juan@example.com']);
$id = $pdo->lastInsertId();

// VersaORM
$user = VersaModel::dispense('users');
$user->name  = 'Juan Pérez';
$user->email = 'juan@example.com';
$user->store(); // id asignado

// Leer
$user = VersaModel::load('users', $user->id);

// Actualizar
$user->email = 'nuevo@example.com';
$user->store();

// Eliminar
$user->trash();
```

#### 🛠️ Query Builder - Consultas Potentes y Seguras
```php
// Búsqueda avanzada con filtros múltiples
$activeUsers = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->whereIn('role', ['admin', 'editor'])
    ->orderBy('created_at', 'desc')
    ->limit(10)
    ->getAll();

// Joins y agregaciones - Dashboard de estadísticas
$userStats = $orm->table('users')
    ->select([
        'users.name',
        'COUNT(posts.id) as total_posts',
        'AVG(posts.views) as avg_views'
    ])
    ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
    ->where('users.status', '=', 'active')
    ->groupBy(['users.id', 'users.name'])
    ->having('total_posts', '>', 5)
    ->getAll();

// Operaciones de escritura masivas
$orm->table('logs')
    ->where('created_at', '<', date('Y-m-d', strtotime('-30 days')))
    ->delete(); // Limpieza de logs antiguos

// Actualización masiva con condiciones
$orm->table('products')
    ->whereIn('category_id', [1, 2, 3])
    ->where('stock', '>', 0)
    ->update(['status' => 'available']);
```

#### Operaciones CRUD Avanzadas
```php
// UPSERT: Insertar si no existe, actualizar si existe
$result = $orm->table('products')->upsert(
    [
        'sku' => 'LAPTOP-001',
        'name' => 'MacBook Pro 16"',
        'price' => 2499.99,
        'stock' => 25
    ],
    ['sku'], // Claves únicas para detectar duplicados
    ['name', 'price', 'stock'] // Campos a actualizar si existe
);

// Método save() inteligente - detecta automáticamente INSERT vs UPDATE
$user = $orm->table('users')->save([
    'email' => 'john@example.com',
    'name' => 'John Updated',
    'role' => 'admin'
], ['email']); // Si existe el email, actualiza; si no, inserta

// insertOrUpdate() - alias intuitivo para upsert
$setting = $orm->table('settings')->insertOrUpdate([
    'key' => 'app_version',
    'value' => '2.1.0',
    'updated_at' => date('Y-m-d H:i:s')
], ['key']);

// replaceInto() - reemplazo completo (solo MySQL)
$backup = $orm->table('user_backups')->replaceInto([
    'user_id' => 123,
    'backup_data' => json_encode($userData),
    'created_at' => date('Y-m-d H:i:s')
]);
```

#### Modelos con Validación
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

## 🔧 Desarrollador (Modo PHP)

En este modo no necesitas compilar nada. Basta con instalar mediante Composer y comenzar.

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
│   └── (binarios opcionales próximos)
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

### 4. 🔒 Modo Freeze para Protección de Esquema
```php
// ✅ PRODUCCIÓN - Activar freeze para proteger esquema
if (app()->environment('production')) {
    $orm->freeze(true);
    echo "🔒 Esquema protegido contra modificaciones DDL";
}

// ✅ DESARROLLO - Freeze selectivo por modelo
$orm->freezeModel(CriticalTable::class, true);

// ❌ BLOQUEADO - En modo freeze esto lanza excepción
try {
    $orm->exec("CREATE TABLE test (id INT)");
} catch (VersaORMException $e) {
    if ($e->getCode() === 'FREEZE_VIOLATION') {
        echo "Operación DDL bloqueada por seguridad";
    }
}
```


## 🚨 Troubleshooting

### Error de conexión a la base de datos
- Verifica las credenciales en `$config`
- Asegúrate de que MySQL esté ejecutándose
- La base de datos `tu_base` se crea automáticamente

### Binario VersaORM no encontrado
En modo PHP / PDO puedes ignorar este mensaje. Cuando el núcleo nativo esté disponible se documentará nuevamente su uso.

## 📚 Documentación

### 📚 Guías de Usuario
- [🚀 Inicio Rápido](docs/docs/getting-started/configuration.md) - Primeros pasos con VersaORM
- [📝 Guía Completa](docs/user-guide/README.md) - Documentación detallada de todos los métodos
- [🛠️ Instalación](docs/getting-started/installation.md) - Guía de instalación y configuración

### 🔧 Documentación para Desarrolladores
- [🏗️ Guía del Desarrollador](docs/contributor-guide/README.md) - Contribuir al proyecto
- [🧪 Aplicación de Ejemplo](example/README.md) - Demo completa To-Do App


## 🌟 Características Principales

### ⚡ Alto Rendimiento (Enfoque Actual)
- Construido sobre PDO con prepared statements reutilizables
- API fluida que reduce código repetitivo y errores
- (Opcional futuro) Núcleo nativo para acelerar aún más sin cambiar tu código

### 🛡️ Seguridad
- Prepared statements automáticos
- Protección Mass Assignment (`$fillable` / `$guarded`)
- Validación declarativa por modelo
- Modo Freeze para bloquear cambios accidentales de esquema

### 🚀 Desarrollo Ágil
- **Creación automática de campos**: Cuando freeze está desactivado, crea columnas automáticamente
- **Detección inteligente de tipos**: Mapeo automático PHP → SQL (string→VARCHAR, int→INT, etc.)
- **Modo fluid**: Desarrollo rápido sin definir esquemas previamente
- **Transición suave**: Del prototipado (freeze OFF) a producción (freeze ON)

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

🚀 **VersaORM (Modo PHP) listo para producción ligera y aprendizaje.**

*Diseñado para claridad • Seguro por defecto • Preparado para crecer*
