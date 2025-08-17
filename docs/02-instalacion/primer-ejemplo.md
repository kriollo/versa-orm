# Primer Ejemplo con VersaORM

## Introducción

¡Es hora de crear tu primera aplicación con VersaORM! En este tutorial construiremos un sistema simple de gestión de tareas (To-Do List) que demuestra las operaciones básicas: crear, leer, actualizar y eliminar datos.

Este ejemplo te mostrará:
- Cómo conectar VersaORM a una base de datos
- Crear y manipular tablas
- Realizar operaciones CRUD básicas
- Manejar errores comunes

## Preparación del Proyecto

### Estructura de Archivos

Crea la siguiente estructura:

```
mi-primer-proyecto/
├── config/
│   └── database.php
├── public/
│   └── index.php
├── vendor/              # Si usas Composer
├── composer.json        # Si usas Composer
└── README.md
```

### Instalación Rápida

Si aún no has instalado VersaORM:

```bash
# Con Composer (recomendado)
composer require versaorm/versaorm

# O descarga manual desde GitHub
```

## Configuración de Base de Datos

### Opción 1: SQLite (Más Simple)

Crea `config/database.php`:

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';

try {
    // Usar SQLite para simplicidad
    $orm = new VersaORM('sqlite:' . __DIR__ . '/../database.db');

    // Habilitar claves foráneas
    $orm->exec("PRAGMA foreign_keys = ON");

    echo "✅ Conexión SQLite establecida\n";
    return $orm;

} catch (PDOException $e) {
    die("❌ Error de conexión: " . $e->getMessage());
}
?>
```

### Opción 2: MySQL

```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';

$config = [
    'host' => 'localhost',
    'dbname' => 'mi_primer_proyecto',
    'username' => 'root',
    'password' => ''
];

try {
    $dsn = "mysql:host={$config['host']};dbname={$config['dbname']};charset=utf8mb4";
    $orm = new VersaORM($dsn, $config['username'], $config['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    echo "✅ Conexión MySQL establecida\n";
    return $orm;

} catch (PDOException $e) {
    die("❌ Error de conexión MySQL: " . $e->getMessage());
}
?>
```

## Creando Tu Primera Aplicación

### Paso 1: Archivo Principal

Crea `public/index.php`:

```php
<?php
// public/index.php
echo "<h1>Mi Primera Aplicación VersaORM</h1>\n";

// Incluir configuración de base de datos
$orm = require_once __DIR__ . '/../config/database.php';

echo "<h2>1. Creando la tabla de tareas</h2>\n";

// Crear tabla de tareas
try {
    $orm->exec("
        CREATE TABLE IF NOT EXISTS tareas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descripcion TEXT,
            completada BOOLEAN DEFAULT 0,
            fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    echo "✅ Tabla 'tareas' creada exitosamente<br>\n";
} catch (Exception $e) {
    echo "❌ Error creando tabla: " . $e->getMessage() . "<br>\n";
}

echo "<h2>2. Insertando tareas de ejemplo</h2>\n";

// Insertar algunas tareas de ejemplo
$tareas_ejemplo = [
    ['titulo' => 'Aprender VersaORM', 'descripcion' => 'Completar el tutorial básico'],
    ['titulo' => 'Crear mi primera app', 'descripcion' => 'Desarrollar una aplicación simple'],
    ['titulo' => 'Leer documentación', 'descripcion' => 'Revisar toda la documentación disponible']
];

foreach ($tareas_ejemplo as $tarea_data) {
    try {
        // Crear nueva tarea usando VersaORM
        $tarea = VersaModel::dispense('tarea');
        $tarea->titulo = $tarea_data['titulo'];
        $tarea->descripcion = $tarea_data['descripcion'];
        $tarea->completada = false;

        // Guardar en la base de datos
        $id = $$tarea->store();
        echo "✅ Tarea creada con ID: $id - '{$tarea->titulo}'<br>\n";

    } catch (Exception $e) {
        echo "❌ Error insertando tarea: " . $e->getMessage() . "<br>\n";
    }
}

echo "<h2>3. Consultando todas las tareas</h2>\n";

try {
    // Obtener todas las tareas
    $todas_las_tareas = $orm->findAll('tarea');

    echo "<ul>\n";
    foreach ($todas_las_tareas as $tarea) {
        $estado = $tarea->completada ? '✅' : '⏳';
        echo "<li>$estado <strong>{$tarea->titulo}</strong> - {$tarea->descripcion}</li>\n";
    }
    echo "</ul>\n";

    echo "<p>Total de tareas: " . count($todas_las_tareas) . "</p>\n";

} catch (Exception $e) {
    echo "❌ Error consultando tareas: " . $e->getMessage() . "<br>\n";
}

echo "<h2>4. Actualizando una tarea</h2>\n";

try {
    // Buscar la primera tarea y marcarla como completada
    $primera_tarea = VersaModel::findOne('tarea', 'ORDER BY id LIMIT 1');

    if ($primera_tarea) {
        $primera_tarea->completada = true;
        $$primera_tarea->store();

        echo "✅ Tarea '{$primera_tarea->titulo}' marcada como completada<br>\n";
    } else {
        echo "⚠️ No se encontraron tareas para actualizar<br>\n";
    }

} catch (Exception $e) {
    echo "❌ Error actualizando tarea: " . $e->getMessage() . "<br>\n";
}

echo "<h2>5. Consultando tareas completadas</h2>\n";

try {
    // Buscar solo tareas completadas
    $tareas_completadas = VersaModel::findAll('tarea', 'completada = ?', [true]);

    echo "<p>Tareas completadas:</p>\n";
    echo "<ul>\n";
    foreach ($tareas_completadas as $tarea) {
        echo "<li>✅ <strong>{$tarea->titulo}</strong></li>\n";
    }
    echo "</ul>\n";

} catch (Exception $e) {
    echo "❌ Error consultando tareas completadas: " . $e->getMessage() . "<br>\n";
}

echo "<h2>6. Usando Query Builder</h2>\n";

try {
    // Ejemplo con Query Builder
    $tareas_pendientes = $orm->table('tareas')
        ->where('completada', '=', false)
        ->orderBy('fecha_creacion', 'DESC')
        ->getAll();

    echo "<p>Tareas pendientes (más recientes primero):</p>\n";
    echo "<ul>\n";
    foreach ($tareas_pendientes as $tarea) {
        echo "<li>⏳ <strong>{$tarea['titulo']}</strong> - {$tarea['descripcion']}</li>\n";
    }
    echo "</ul>\n";

} catch (Exception $e) {
    echo "❌ Error con Query Builder: " . $e->getMessage() . "<br>\n";
}

echo "<h2>7. Estadísticas</h2>\n";

try {
    // Contar tareas por estado
    $total_tareas = $orm->count('tarea');
    $tareas_completadas = $orm->count('tarea', 'completada = ?', [true]);
    $tareas_pendientes = $total_tareas - $tareas_completadas;

    echo "<div style='background: #f0f0f0; padding: 10px; border-radius: 5px;'>\n";
    echo "<h3>Resumen de Tareas</h3>\n";
    echo "<p>📊 Total de tareas: <strong>$total_tareas</strong></p>\n";
    echo "<p>✅ Completadas: <strong>$tareas_completadas</strong></p>\n";
    echo "<p>⏳ Pendientes: <strong>$tareas_pendientes</strong></p>\n";
    echo "</div>\n";

} catch (Exception $e) {
    echo "❌ Error calculando estadísticas: " . $e->getMessage() . "<br>\n";
}

echo "<h2>¡Felicitaciones! 🎉</h2>\n";
echo "<p>Has completado tu primer ejemplo con VersaORM. Has aprendido a:</p>\n";
echo "<ul>\n";
echo "<li>✅ Conectar a una base de datos</li>\n";
echo "<li>✅ Crear tablas</li>\n";
echo "<li>✅ Insertar datos con <code>dispense()</code> y <code>store()</code></li>\n";
echo "<li>✅ Consultar datos con <code>findAll()</code> y <code>find()</code></li>\n";
echo "<li>✅ Actualizar registros</li>\n";
echo "<li>✅ Usar el Query Builder</li>\n";
echo "<li>✅ Contar registros</li>\n";
echo "</ul>\n";

echo "<h3>Próximos Pasos</h3>\n";
echo "<p>Ahora puedes:</p>\n";
echo "<ul>\n";
echo "<li>📖 Leer la <a href='../03-basico/'>documentación de CRUD básico</a></li>\n";
echo "<li>🔧 Explorar el <a href='../04-query-builder/'>Query Builder avanzado</a></li>\n";
echo "<li>🔗 Aprender sobre <a href='../05-relaciones/'>relaciones entre modelos</a></li>\n";
echo "</ul>\n";
?>
```

## Ejecutando el Ejemplo

### Método 1: Servidor PHP Integrado

```bash
# Navegar al directorio del proyecto
cd mi-primer-proyecto

# Iniciar servidor de desarrollo
php -S localhost:8000 -t public

# Abrir en el navegador
# http://localhost:8000
```

### Método 2: XAMPP/WAMP

1. Copia tu proyecto a `htdocs/mi-primer-proyecto`
2. Abre `http://localhost/mi-primer-proyecto/public/`

### Método 3: Línea de Comandos

```bash
# Ejecutar directamente
php public/index.php
```

## Explicación del Código

### 1. Conexión a la Base de Datos

```php
$orm = new VersaORM('sqlite:database.db');
```

**¿Qué hace?** Crea una conexión a SQLite
**Devuelve:** Objeto VersaORM listo para usar

### 2. Crear Registros

```php
$tarea = VersaModel::dispense('tarea');  // Crea un objeto vacío
$tarea->titulo = 'Mi tarea';       // Asigna propiedades
$id = $$tarea->store();         // Guarda en BD
```

**¿Qué hace?**
- `dispense()` crea un objeto VersaModel vacío
- Asignas propiedades como si fueran variables
- `store()` inserta o actualiza en la base de datos

**Devuelve:** `store()` devuelve el ID del registro

### 3. Consultar Registros

```php
$todas = $orm->findAll('tarea');           // Todas las tareas
$una = VersaModel::findOne('tarea', 'id = ?', [1]); // Una tarea específica
$algunas = VersaModel::findAll('tarea', 'completada = ?', [false]); // Con condición
```

**¿Qué devuelve?**
- `findAll()`: Array de objetos VersaModel
- `findOne()`: Un objeto VersaModel o null
- `find()`: Array de objetos VersaModel

### 4. Query Builder

```php
$resultados = $orm->table('tareas')
    ->where('completada', '=', false)
    ->orderBy('fecha_creacion', 'DESC')
    ->getAll();
```

**¿Qué hace?** Construye consultas SQL de forma fluida
**Devuelve:** Array de arrays asociativos

## Comparación con SQL Tradicional

### VersaORM vs SQL

| Operación | VersaORM | SQL Equivalente |
|-----------|----------|-----------------|
| **Insertar** | `$tarea = VersaModel::dispense('tarea'); $tarea->titulo = 'Test'; $$tarea->store();` | `INSERT INTO tareas (titulo) VALUES ('Test')` |
| **Consultar Todo** | `$orm->findAll('tarea')` | `SELECT * FROM tareas` |
| **Consultar Con Condición** | `VersaModel::findAll('tarea', 'completada = ?', [true])` | `SELECT * FROM tareas WHERE completada = 1` |
| **Actualizar** | `$tarea->completada = true; $$tarea->store();` | `UPDATE tareas SET completada = 1 WHERE id = ?` |
| **Contar** | `$orm->count('tarea')` | `SELECT COUNT(*) FROM tareas` |

## Versión Interactiva (Opcional)

Si quieres hacer el ejemplo más interactivo, crea `public/interactive.php`:

```php
<?php
// public/interactive.php
$orm = require_once __DIR__ . '/../config/database.php';

// Crear tabla si no existe
$orm->exec("
    CREATE TABLE IF NOT EXISTS tareas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        descripcion TEXT,
        completada BOOLEAN DEFAULT 0,
        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
    )
");

// Procesar formulario
if ($_POST['accion'] ?? false) {
    switch ($_POST['accion']) {
        case 'crear':
            $tarea = VersaModel::dispense('tarea');
            $tarea->titulo = $_POST['titulo'] ?? '';
            $tarea->descripcion = $_POST['descripcion'] ?? '';
            $$tarea->store();
            $mensaje = "✅ Tarea creada: {$tarea->titulo}";
            break;

        case 'completar':
            $tarea = VersaModel::load('tarea', $_POST['id']);
            $tarea->completada = true;
            $$tarea->store();
            $mensaje = "✅ Tarea completada: {$tarea->titulo}";
            break;

        case 'eliminar':
            $tarea = VersaModel::load('tarea', $_POST['id']);
            $titulo = $tarea->titulo;
            $$tarea->trash();
            $mensaje = "🗑️ Tarea eliminada: $titulo";
            break;
    }
}

// Obtener todas las tareas
$tareas = $orm->findAll('tarea', 'ORDER BY fecha_creacion DESC');
?>

<!DOCTYPE html>
<html>
<head>
    <title>Lista de Tareas - VersaORM</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .tarea { background: #f9f9f9; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .completada { background: #e8f5e8; text-decoration: line-through; }
        form { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        input, textarea, button { margin: 5px; padding: 8px; }
        button { background: #007cba; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .btn-danger { background: #dc3545; }
        .btn-success { background: #28a745; }
    </style>
</head>
<body>
    <h1>🚀 Lista de Tareas con VersaORM</h1>

    <?php if (isset($mensaje)): ?>
        <div style="background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <?= $mensaje ?>
        </div>
    <?php endif; ?>

    <form method="POST">
        <h3>➕ Crear Nueva Tarea</h3>
        <input type="hidden" name="accion" value="crear">
        <input type="text" name="titulo" placeholder="Título de la tarea" required style="width: 300px;">
        <br>
        <textarea name="descripcion" placeholder="Descripción (opcional)" style="width: 300px; height: 60px;"></textarea>
        <br>
        <button type="submit">Crear Tarea</button>
    </form>

    <h3>📋 Mis Tareas (<?= count($tareas) ?>)</h3>

    <?php if (empty($tareas)): ?>
        <p>No hay tareas. ¡Crea tu primera tarea arriba!</p>
    <?php else: ?>
        <?php foreach ($tareas as $tarea): ?>
            <div class="tarea <?= $tarea->completada ? 'completada' : '' ?>">
                <h4><?= $tarea->completada ? '✅' : '⏳' ?> <?= htmlspecialchars($tarea->titulo) ?></h4>
                <?php if ($tarea->descripcion): ?>
                    <p><?= htmlspecialchars($tarea->descripcion) ?></p>
                <?php endif; ?>
                <small>Creada: <?= $tarea->fecha_creacion ?></small>

                <div style="margin-top: 10px;">
                    <?php if (!$tarea->completada): ?>
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="accion" value="completar">
                            <input type="hidden" name="id" value="<?= $tarea->id ?>">
                            <button type="submit" class="btn-success">Completar</button>
                        </form>
                    <?php endif; ?>

                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="accion" value="eliminar">
                        <input type="hidden" name="id" value="<?= $tarea->id ?>">
                        <button type="submit" class="btn-danger" onclick="return confirm('¿Eliminar esta tarea?')">Eliminar</button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <hr>
    <h3>📊 Estadísticas</h3>
    <?php
    $total = count($tareas);
    $completadas = count(array_filter($tareas, fn($t) => $t->completada));
    $pendientes = $total - $completadas;
    ?>
    <p>Total: <strong><?= $total ?></strong> | Completadas: <strong><?= $completadas ?></strong> | Pendientes: <strong><?= $pendientes ?></strong></p>

    <hr>
    <p><em>Este ejemplo demuestra las operaciones básicas de VersaORM: crear, leer, actualizar y eliminar datos.</em></p>
</body>
</html>
```

## Solución de Problemas Comunes

### Error: "Class 'VersaORM' not found"

**Causa:** Autoload no incluido correctamente

**Solución:**
```php
// Verificar que esta línea esté al inicio
require_once __DIR__ . '/../vendor/autoload.php';

// O para instalación manual
require_once __DIR__ . '/../lib/versaorm/autoload.php';
```

### Error: "SQLSTATE[HY000] [14] unable to open database file"

**Causa:** Permisos de archivo SQLite

**Solución:**
```bash
# Linux/macOS
chmod 664 database.db
chmod 775 .

# O usar ruta absoluta
$orm = new VersaORM('sqlite:' . __DIR__ . '/database.db');
```

### Error: "Table doesn't exist"

**Causa:** Tabla no creada

**Solución:**
```php
// Siempre crear tablas antes de usarlas
$orm->exec("CREATE TABLE IF NOT EXISTS tareas (...)");
```

### Datos No Se Muestran

**Causa:** Error en consulta o datos vacíos

**Solución:**
```php
// Verificar si hay datos
$tareas = $orm->findAll('tarea');
echo "Encontradas: " . count($tareas) . " tareas\n";

// Verificar errores
try {
    $tareas = $orm->findAll('tarea');
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

## Próximos Pasos

¡Felicitaciones! Has completado tu primer ejemplo con VersaORM. Ahora puedes:

1. **Explorar CRUD Básico**: Lee la [documentación de operaciones básicas](../03-basico/)
2. **Query Builder**: Aprende consultas más complejas en [Query Builder](../04-query-builder/)
3. **Relaciones**: Descubre cómo conectar tablas en [Relaciones](../05-relaciones/)
4. **Funciones Avanzadas**: Explora características avanzadas en [Avanzado](../06-avanzado/)

## Resumen

En este ejemplo has aprendido:

- ✅ **Conectar** VersaORM a una base de datos
- ✅ **Crear tablas** con SQL
- ✅ **Insertar datos** con `dispense()` y `store()`
- ✅ **Consultar datos** con `findAll()`, `findOne()`, `find()`
- ✅ **Actualizar registros** modificando propiedades
- ✅ **Usar Query Builder** para consultas fluidas
- ✅ **Contar registros** con `count()`
- ✅ **Manejar errores** con try-catch

**¿Qué devuelve cada método?**
- `dispense()` → Objeto VersaModel vacío
- `store()` → ID del registro guardado
- `findAll()` → Array de objetos VersaModel
- `findOne()` → Un objeto VersaModel o null
- `find()` → Array de objetos VersaModel
- Query Builder → Array de arrays asociativos

¡Ahora estás listo para crear aplicaciones más complejas con VersaORM!
