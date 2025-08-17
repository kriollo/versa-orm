# 🛠️ Configuración de Ejemplos

Esta carpeta contiene los scripts y archivos de configuración necesarios para ejecutar todos los ejemplos de la documentación de VersaORM. Proporciona un entorno consistente y datos de prueba realistas.

## 📁 Archivos Incluidos

### `setup_database.php`
**Script principal de configuración**
- Crea las tablas de ejemplo (users, posts, tags, post_tags)
- Inserta datos de prueba consistentes y realistas
- Configura relaciones entre tablas
- Muestra un resumen completo de la configuración
- Verifica que todo funcione correctamente

### `database_config.php`
**Configuración de base de datos**
- Tipo de base de datos (SQLite por defecto para simplicidad)
- Parámetros de conexión personalizables
- Configuraciones alternativas para MySQL y PostgreSQL
- Variables de entorno para seguridad

### `example_config.php`
**Funciones helper para ejemplos**
- `getExampleORM()` - Inicializa VersaORM con la configuración
- `showResults()` - Muestra resultados de forma legible
- `showSQLEquivalent()` - Muestra el SQL equivalente
- `showReturnType()` - Explica qué devuelve cada método
- `formatOutput()` - Formatea salida para mejor legibilidad

### `test_setup.php`
**Verificación de configuración**
- Prueba la conexión a la base de datos
- Verifica que las tablas existan
- Confirma que los datos de ejemplo estén disponibles
- Ejecuta consultas de prueba básicas

## 🔍 Scripts de Validación

### `validate_documentation.php`
**Validador principal de documentación**
- Extrae y valida todos los ejemplos de código PHP
- Verifica sintaxis y ejecución correcta
- Confirma tipos de retorno documentados
- Genera reporte detallado de problemas

### `multi_db_validator.php`
**Validador de compatibilidad multi-base de datos**
- Prueba ejemplos en SQLite, MySQL y PostgreSQL
- Verifica compatibilidad del SQL generado
- Reporta diferencias entre motores de BD
- Confirma portabilidad de ejemplos

### `format_checker.php`
**Verificador de consistencia de formato**
- Valida estructura de títulos y subtítulos
- Verifica formato de bloques de código
- Confirma consistencia de enlaces internos
- Revisa estilo de documentación

### `run_all_validations.php`
**Script maestro de validación**
- Ejecuta todas las validaciones disponibles
- Genera reporte consolidado de resultados
- Opción de validación rápida (--quick)
- Reportes detallados en formato JSON

### `database_test_config.php`
**Configuraciones para pruebas multi-BD**
- Configuraciones específicas para validación
- Soporte para variables de entorno
- Configuración automática de motores disponibles

## 🚀 Uso Rápido

### 1. Configuración Inicial (Recomendado)

```bash
# Ejecutar desde la raíz del proyecto
php docs/setup/setup_database.php
```

Este comando:
- ✅ Crea la base de datos SQLite
- ✅ Configura todas las tablas necesarias
- ✅ Inserta datos de ejemplo realistas
- ✅ Verifica que todo funcione correctamente

### 2. Verificar Configuración

```bash
# Opcional: verificar que todo esté bien
php docs/setup/test_setup.php
```

### 3. Personalizar Base de Datos (Opcional)

Para usar MySQL o PostgreSQL, edita `database_config.php`:

```php
// Para MySQL
return [
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'versaorm_docs',
    'username' => 'tu_usuario',
    'password' => 'tu_password',
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
];

// Para PostgreSQL
return [
    'driver' => 'pgsql',
    'host' => 'localhost',
    'database' => 'versaorm_docs',
    'username' => 'tu_usuario',
    'password' => 'tu_password',
    'charset' => 'utf8',
];
```

### 4. Usar en Ejemplos

Todos los ejemplos de la documentación incluyen:

```php
require_once __DIR__ . '/../setup/example_config.php';
$orm = getExampleORM();

// Ahora puedes usar $orm en tus ejemplos
$users = $orm->table('users')->getAll();
showResults($users, 'Todos los usuarios');
```

## 🧪 Validación de Documentación

### Validación Completa
Ejecuta todas las validaciones (ejemplos, formato, compatibilidad multi-BD):
```bash
php docs/setup/run_all_validations.php
```

### Validación Rápida
Solo validación básica y formato (más rápido):
```bash
php docs/setup/run_all_validations.php --quick
```

### Validaciones Individuales

**Validar ejemplos de código:**
```bash
php docs/setup/validate_documentation.php
```

**Verificar formato:**
```bash
php docs/setup/format_checker.php
```

**Probar compatibilidad multi-BD:**
```bash
php docs/setup/multi_db_validator.php
```

### Reportes Generados

Los scripts de validación generan reportes detallados:
- `validation_report.json` - Reporte de validación básica
- `format_report.json` - Reporte de consistencia de formato
- `multi_db_report.json` - Reporte de compatibilidad multi-BD
- `master_validation_report.json` - Reporte consolidado

## 📊 Estructura de Datos

### Tabla `users` (Usuarios)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Tabla `posts` (Publicaciones)
```sql
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    user_id INTEGER NOT NULL,
    published BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Tabla `tags` (Etiquetas)
```sql
CREATE TABLE tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL
);
```

### Tabla `post_tags` (Relación Posts-Tags)
```sql
CREATE TABLE post_tags (
    post_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);
```

## 📈 Datos de Ejemplo Incluidos

### Usuarios (4 registros)
- **Ana García** (ana@example.com) - Activa
- **Carlos López** (carlos@example.com) - Activo
- **María Rodríguez** (maria@example.com) - Activa
- **Juan Pérez** (juan@example.com) - Inactivo

### Posts (5 registros)
- **4 publicados** con contenido completo
- **1 borrador** para ejemplos de filtrado
- Distribuidos entre diferentes usuarios

### Tags (6 registros)
- tecnología, php, orm, base-de-datos, tutorial, avanzado

### Relaciones Post-Tags (8 registros)
- Cada post tiene 1-3 tags asociados
- Ejemplos realistas de relaciones muchos-a-muchos

## 🎯 Casos de Uso Cubiertos

Estos datos permiten demostrar:
- ✅ **CRUD básico**: Crear, leer, actualizar, eliminar
- ✅ **Filtros**: Usuarios activos/inactivos, posts publicados/borradores
- ✅ **Relaciones 1:N**: Usuario → Posts
- ✅ **Relaciones N:M**: Posts ↔ Tags
- ✅ **JOINs**: Consultas entre múltiples tablas
- ✅ **Agregaciones**: Contar posts por usuario, tags por post
- ✅ **Paginación**: Suficientes registros para ejemplos
- ✅ **Validación**: Emails únicos, campos requeridos

## 🔗 Enlaces Relacionados

- [Instalación y Configuración](../02-instalacion/README.md)
- [CRUD Básico](../03-basico/README.md)
- [Relaciones](../05-relaciones/README.md)
- [Documentación Principal](../README.md)

---

**¿Problemas con la configuración?** Revisa la [guía de instalación](../02-instalacion/instalacion.md) o la [guía de configuración](../02-instalacion/configuracion.md).
