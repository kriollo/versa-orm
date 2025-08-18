# Instalación de VersaORM

## Introducción

Esta guía te llevará paso a paso por el proceso de instalación de VersaORM en tu proyecto PHP. VersaORM es compatible con PHP 7.4+ y funciona con MySQL, PostgreSQL y SQLite.

## Requisitos del Sistema

### Requisitos Mínimos
- **PHP**: 7.4 o superior
- **PDO**: Extensión PDO habilitada
- **Base de datos**: MySQL 5.7+, PostgreSQL 9.6+, o SQLite 3.8+

### Verificar Requisitos

Antes de instalar, verifica que tu sistema cumple los requisitos:

```php
<?php
// Verificar versión de PHP
echo "Versión de PHP: " . PHP_VERSION . "\n";

// Verificar PDO
if (extension_loaded('pdo')) {
    echo "✅ PDO está disponible\n";

    // Verificar drivers disponibles
    $drivers = PDO::getAvailableDrivers();
    echo "Drivers PDO disponibles: " . implode(', ', $drivers) . "\n";
} else {
    echo "❌ PDO no está disponible\n";
}

// Verificar extensiones específicas
$extensions = ['pdo_mysql', 'pdo_pgsql', 'pdo_sqlite'];
foreach ($extensions as $ext) {
    if (extension_loaded($ext)) {
        echo "✅ $ext está disponible\n";
    } else {
        echo "⚠️ $ext no está disponible\n";
    }
}
?>
```

## Método 1: Instalación con Composer (Recomendado)

### Paso 1: Instalar Composer

Si no tienes Composer instalado, descárgalo desde [getcomposer.org](https://getcomposer.org/):

```bash
# En Windows (PowerShell)
Invoke-WebRequest -Uri https://getcomposer.org/installer -OutFile composer-setup.php
php composer-setup.php
php -r "unlink('composer-setup.php');"

# En Linux/macOS
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

### Paso 2: Crear tu Proyecto

```bash
# Crear directorio del proyecto
mkdir mi-proyecto-versaorm
cd mi-proyecto-versaorm

# Inicializar Composer
composer init
```

### Paso 3: Instalar VersaORM

```bash
# Instalar VersaORM
composer require versaorm/versaorm

# Verificar instalación
composer show versaorm/versaorm
```

### Paso 4: Verificar Instalación

Crea un archivo `test-instalacion.php`:

```php
<?php
require_once 'vendor/autoload.php';

try {
    // Probar con SQLite (no requiere servidor) - forma recomendada (array)
    $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
    VersaModel::setORM($orm);
    echo "✅ VersaORM instalado correctamente\n";
    echo "Versión: " . $orm->getVersion() . "\n";
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
?>
```

Ejecuta el test:
```bash
php test-instalacion.php
```

## Método 2: Instalación Manual

### Paso 1: Descargar VersaORM

```bash
# Opción A: Con Git
git clone https://github.com/versaorm/versaorm-php.git
cd versaorm-php

# Opción B: Descargar ZIP
# Descarga desde GitHub y extrae en tu directorio de proyecto
```

### Paso 2: Estructura de Archivos

Organiza tu proyecto así:

```
mi-proyecto/
├── lib/
│   └── versaorm/          # Archivos de VersaORM
│       ├── src/
│       └── autoload.php
├── config/
│   └── database.php
├── models/
├── public/
│   └── index.php
└── composer.json          # Opcional
```

### Paso 3: Configurar Autoload

Crea `lib/versaorm/autoload.php`:

```php
<?php
spl_autoload_register(function ($class) {
    $prefix = 'VersaORM\\';
    $base_dir = __DIR__ . '/src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});
?>
```

### Paso 4: Incluir en tu Proyecto

```php
<?php
// En tus archivos PHP
require_once 'lib/versaorm/autoload.php';

// Ahora puedes usar VersaORM (array recomendado en lugar de DSN)
$orm = new VersaORM([
    'driver' => 'sqlite',
    'database' => __DIR__ . '/database.db'
]);
VersaModel::setORM($orm);
?>
```

## Instalación en Diferentes Entornos

### XAMPP (Windows)

1. **Instalar XAMPP** desde [apachefriends.org](https://www.apachefriends.org/)

2. **Ubicar tu proyecto**:
   ```
   C:\xampp\htdocs\mi-proyecto\
   ```

3. **Instalar Composer en XAMPP**:
   ```bash
   # Abrir terminal en C:\xampp\htdocs\mi-proyecto\
   composer require versaorm/versaorm
   ```

4. **Configurar base de datos**:
   ```php
   <?php
   // Para MySQL en XAMPP (forma recomendada con array)
   $orm = new VersaORM([
       'driver' => 'mysql',
       'host' => 'localhost',
       'database' => 'mi_bd',
       'username' => 'root',
       'password' => ''
   ]);
   VersaModel::setORM($orm);
   ?>
   ```

### WAMP (Windows)

1. **Instalar WAMP** desde [wampserver.com](http://www.wampserver.com/)

2. **Ubicar proyecto**:
   ```
   C:\wamp64\www\mi-proyecto\
   ```

3. **Seguir pasos similares a XAMPP**

### LAMP (Linux)

1. **Instalar LAMP**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install apache2 mysql-server php php-mysql php-pdo

   # CentOS/RHEL
   sudo yum install httpd mariadb-server php php-mysql php-pdo
   ```

2. **Instalar Composer**:
   ```bash
   curl -sS https://getcomposer.org/installer | php
   sudo mv composer.phar /usr/local/bin/composer
   ```

3. **Crear proyecto**:
   ```bash
   cd /var/www/html
   sudo mkdir mi-proyecto
   cd mi-proyecto
   composer require versaorm/versaorm
   ```

### Docker

Crea un `docker-compose.yml`:

```yaml
version: '3.8'
services:
  web:
    image: php:8.1-apache
    ports:
      - "8080:80"
    volumes:
      - ./src:/var/www/html
    depends_on:
      - db
    environment:
      - DB_HOST=db
      - DB_NAME=versaorm_app
      - DB_USER=root
      - DB_PASS=password

  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: versaorm_app
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data:
```

Ejecutar:
```bash
docker-compose up -d
docker-compose exec web composer require versaorm/versaorm
```

## Solución de Problemas Comunes

### Error: "Class 'VersaORM' not found"

**Causa**: Autoload no configurado correctamente

**Solución**:
```php
<?php
// Verificar que el autoload esté incluido
require_once 'vendor/autoload.php';  // Con Composer
// O
require_once 'lib/versaorm/autoload.php';  // Instalación manual
?>
```

### Error: "could not find driver"

**Causa**: Driver PDO no instalado

**Solución**:
```bash
# Ubuntu/Debian
sudo apt install php-mysql php-pgsql php-sqlite3

# CentOS/RHEL
sudo yum install php-mysql php-pgsql php-sqlite

# Windows (XAMPP)
# Editar php.ini y descomentar:
# extension=pdo_mysql
# extension=pdo_pgsql
# extension=pdo_sqlite
```

### Error de Permisos (Linux)

**Causa**: Permisos incorrectos en directorios

**Solución**:
```bash
# Dar permisos al directorio del proyecto
sudo chown -R www-data:www-data /var/www/html/mi-proyecto
sudo chmod -R 755 /var/www/html/mi-proyecto

# Para desarrollo local
sudo chown -R $USER:$USER /var/www/html/mi-proyecto
```

### Error: "Access denied for user"

**Causa**: Credenciales de base de datos incorrectas

**Solución**:
```php
<?php
// Verificar credenciales
$host = 'localhost';
$dbname = 'mi_bd';
$username = 'mi_usuario';
$password = 'mi_password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    echo "✅ Conexión exitosa";
} catch (PDOException $e) {
    echo "❌ Error: " . $e->getMessage();
}
?>
```

## Verificación Final

Crea un script completo de verificación `verificar-instalacion.php`:

```php
<?php
echo "=== Verificación de Instalación VersaORM ===\n\n";

// 1. Verificar PHP
echo "1. Versión de PHP: " . PHP_VERSION;
if (version_compare(PHP_VERSION, '7.4.0', '>=')) {
    echo " ✅\n";
} else {
    echo " ❌ (Requiere 7.4+)\n";
}

// 2. Verificar PDO
echo "2. PDO: ";
if (extension_loaded('pdo')) {
    echo "✅\n";
    echo "   Drivers: " . implode(', ', PDO::getAvailableDrivers()) . "\n";
} else {
    echo "❌\n";
}

// 3. Verificar VersaORM
echo "3. VersaORM: ";
try {
    if (file_exists('vendor/autoload.php')) {
        require_once 'vendor/autoload.php';
    } elseif (file_exists('lib/versaorm/autoload.php')) {
        require_once 'lib/versaorm/autoload.php';
    }

    $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
    VersaModel::setORM($orm);
    echo "✅\n";
    echo "   Versión: " . $orm->getVersion() . "\n";
} catch (Exception $e) {
    echo "❌\n";
    echo "   Error: " . $e->getMessage() . "\n";
}

echo "\n=== Instalación Completa ===\n";
?>
```

## Siguiente Paso

Una vez que VersaORM esté instalado correctamente, el siguiente paso es [configurar la conexión a tu base de datos](configuracion.md).

## Resumen

- ✅ **Composer** es el método recomendado para instalar VersaORM
- ✅ **Verificar requisitos** antes de instalar
- ✅ **Probar instalación** con scripts de verificación
- ✅ **Solucionar problemas** comunes con las guías incluidas
- ✅ VersaORM funciona en **cualquier entorno** PHP estándar
