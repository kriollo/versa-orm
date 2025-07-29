# 📚 Guía Completa del Usuario - VersaORM

**Referencia completa de todos los métodos y funcionalidades de VersaORM-PHP**

Esta guía proporciona documentación detallada sobre cómo utilizar todas las funcionalidades de VersaORM-PHP, incluyendo ejemplos prácticos y mejores prácticas.

## 🔌 Configuración y Conexión

### Configuración Básica

```php
use VersaORM\VersaORM;
use VersaORM\Model;

// Crear instancia del ORM
$orm = new VersaORM([
    'driver' => 'mysql',        // mysql, postgresql, sqlite
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'mi_app',
    'username' => 'usuario',
    'password' => 'password',
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci'
]);

// Configurar modelos (necesario para métodos estáticos)
Model::setORM($orm);
```

### Configuración para Múltiples Bases de Datos

```php
// Base de datos principal
$mainDb = new VersaORM($mainConfig);

// Base de datos de log
$logDb = new VersaORM($logConfig);

// Usar diferentes conexiones
$users = $mainDb->table('users')->get();
$logs = $logDb->table('access_logs')->get();
```

## QueryBuilder

El QueryBuilder es la herramienta principal para construir consultas SQL de forma programática y segura.

### Métodos de Selección
- `get()`: Devuelve un array de resultados.
- `first()`: Devuelve el primer resultado o `null`.
- `find($id)`: Busca un registro por su clave primaria.
- `count()`: Devuelve el número de registros.
- `exists()`: Verifica si existe al menos un registro.

### Cláusulas Comunes
- `select(array $columns)`
- `where(string $column, string $operator, $value)`
- `orWhere(...)`
- `whereIn(string $column, array $values)`
- `whereNotIn(...)`
- `whereNull(string $column)`
- `whereNotNull(...)`
- `join(string $table, ...)`
- `leftJoin(...)`
- `rightJoin(...)`
- `orderBy(string $column, string $direction)`
- `groupBy(string $column)`
- `limit(int $count)`
- `offset(int $count)`

### Operaciones de Modificación
- `insert(array $data)`
- `insertGetId(array $data)`
- `update(array $data)`
- `delete()`

## Modelos ORM (ActiveRecord)

Permite trabajar con registros como si fueran objetos.

### Crear un Modelo (dispense)
```php
$user = VersaORM::table('users')->dispense();
$user->name = 'Nuevo Usuario';
$user->email = 'nuevo@example.com';
$user->store(); // Guarda el nuevo registro
```

### Cargar y Actualizar
```php
// Cargar un modelo por su ID
$user = VersaORM::table('users')->dispense();
$user->load(1);

// Actualizar y guardar
$user->name = 'Nombre Actualizado';
$user->store();
```

### Eliminar
```php
$user = VersaORM::table('users')->dispense();
$user->load(1);
$user->trash(); // Elimina el registro
```

## Manejo de Errores

VersaORM proporciona mensajes de error detallados para ayudarte a diagnosticar y resolver problemas rápidamente.

### Ejemplo Básico

```php
try {
    $user = VersaORM::table('usuarios')
        ->where('id', '=', 999)
        ->firstOrFail();
} catch (\Exception $e) {
    // El mensaje de error incluye sugerencias útiles
    echo "Error: " . $e->getMessage();
}
```

### Tipos de Errores Comunes

1. **Errores de Conexión**
   ```
   VersaORM Error [CONNECTION_FAILED]: Could not connect to database
   Suggestions:
   - Check database server is running
   - Verify connection parameters (host, port, credentials)
   - Check network connectivity
   ```

2. **Tabla No Encontrada**
   ```
   VersaORM Error [TABLE_NOT_FOUND]: Table 'mibase.usuarios' doesn't exist
   Suggestions:
   - Check if the table name is spelled correctly
   - Verify the table exists in the database
   - Ensure you have permissions to access the table
   ```

3. **Error de Sintaxis SQL**
   ```
   VersaORM Error [SYNTAX_ERROR]: You have an error in your SQL syntax...
   Suggestions:
   - Check SQL syntax for typos
   - Verify proper use of quotes and parentheses
   ```

### Buenas Prácticas

1. **Siempre usa try-catch** para manejar posibles errores en operaciones de base de datos.
2. **Registra los errores** en un archivo de log para diagnóstico.
3. **Muestra mensajes genéricos** al usuario final, pero registra los detalles completos.

## Funcionalidades Adicionales

### Consultas Crudas (Raw)
```php
$results = VersaORM::exec('SELECT * FROM users WHERE activo = ?', [true]);
```

### Introspección de Esquema
```php
$tables = VersaORM::schema('tables');
$columns = VersaORM::schema('columns', 'users');
```

### Gestión de Caché
```php
VersaORM::cache('enable');
VersaORM::cache('clear');
$status = VersaORM::cache('status');
```
