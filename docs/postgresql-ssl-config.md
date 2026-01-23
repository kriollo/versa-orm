# Configuración SSL para PostgreSQL en VersaORM-PHP

## Introducción

VersaORM-PHP soporta todas las opciones de SSL/TLS para conexiones a PostgreSQL. Esto te permite controlar cómo se establece la conexión encriptada entre tu aplicación y el servidor de base de datos.

## Opciones de SSL Disponibles

### `sslmode` - Modo de SSL

Controla cómo se maneja la conexión SSL:

| Modo | Descripción | Uso Recomendado |
|------|-------------|-----------------|
| `disable` | Sin SSL (sin encriptación) | Desarrollo local, red interna confiable |
| `allow` | Intenta sin SSL primero, usa SSL si el servidor lo requiere | Rara vez necesario |
| `prefer` | Intenta con SSL primero, acepta sin SSL si falla | **Por defecto en PostgreSQL** |
| `require` | Requiere SSL, falla si no está disponible | Producción (mínimo recomendado) |
| `verify-ca` | Requiere SSL y verifica el certificado CA | Producción con mayor seguridad |
| `verify-full` | Requiere SSL, verifica CA y hostname | **Máxima seguridad en producción** |

### Otras Opciones de SSL

- **`sslcert`**: Ruta al archivo de certificado del cliente (`.pem`)
- **`sslkey`**: Ruta al archivo de clave privada del cliente (`.pem`)
- **`sslrootcert`**: Ruta al archivo de certificado CA raíz (`.pem`)

## Ejemplos de Configuración

### 1. Desarrollo Local (sin SSL)

Para desarrollo local donde no necesitas encriptación:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'localhost',
    'port' => 5432,
    'database' => 'mi_base_datos',
    'username' => 'usuario_dev',
    'password' => 'password_dev',
    'sslmode' => 'disable',  // Sin SSL para desarrollo local
];

$orm = new VersaORM\VersaORM($config);
```

### 2. Producción Básica (SSL requerido)

Para producción donde necesitas SSL pero sin verificación de certificados:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'db.miapp.com',
    'port' => 5432,
    'database' => 'produccion_db',
    'username' => 'app_user',
    'password' => getenv('DB_PASSWORD'),
    'sslmode' => 'require',  // Requiere SSL
];

$orm = new VersaORM\VersaORM($config);
```

### 3. Producción con Verificación de Certificados

Para máxima seguridad, verifica el certificado CA:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'secure-db.miapp.com',
    'port' => 5432,
    'database' => 'produccion_db',
    'username' => 'app_user',
    'password' => getenv('DB_PASSWORD'),
    'sslmode' => 'verify-ca',  // Verifica el certificado CA
    'sslrootcert' => '/path/to/ca-certificate.pem',  // Certificado CA
];

$orm = new VersaORM\VersaORM($config);
```

### 4. Producción con Autenticación Mutua (mTLS)

Para máxima seguridad con certificados cliente y servidor:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'secure-db.miapp.com',
    'port' => 5432,
    'database' => 'produccion_db',
    'username' => 'app_user',
    'password' => getenv('DB_PASSWORD'),
    'sslmode' => 'verify-full',  // Verifica CA y hostname
    'sslcert' => '/path/to/client-certificate.pem',  // Certificado del cliente
    'sslkey' => '/path/to/client-key.pem',  // Clave privada del cliente
    'sslrootcert' => '/path/to/ca-certificate.pem',  // Certificado CA raíz
];

$orm = new VersaORM\VersaORM($config);
```

### 5. Usando Variables de Entorno

Recomendado para mantener las credenciales fuera del código:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => getenv('DB_HOST') ?: 'localhost',
    'port' => (int) (getenv('DB_PORT') ?: 5432),
    'database' => getenv('DB_NAME'),
    'username' => getenv('DB_USER'),
    'password' => getenv('DB_PASSWORD'),
    'sslmode' => getenv('DB_SSLMODE') ?: 'prefer',
];

$orm = new VersaORM\VersaORM($config);
```

Archivo `.env`:
```env
DB_HOST=db.miapp.com
DB_PORT=5432
DB_NAME=produccion_db
DB_USER=app_user
DB_PASSWORD=secreto_super_seguro
DB_SSLMODE=require
```

## Configuración Específica por Entorno

### Docker Compose

Ejemplo de configuración en `docker-compose.yml`:

```yaml
version: '3.8'
services:
  app:
    image: php:8.3-fpm
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: app_db
      DB_USER: app_user
      DB_PASSWORD: app_password
      DB_SSLMODE: disable  # Deshabilitado dentro de la red Docker
    depends_on:
      - postgres
  
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: app_db
      POSTGRES_USER: app_user
      POSTGRES_PASSWORD: app_password
```

### AWS RDS PostgreSQL

Para conectar a AWS RDS con SSL:

```php
<?php

$config = [
    'driver' => 'pgsql',
    'host' => 'mydb.xxxxxxxxxxxx.us-east-1.rds.amazonaws.com',
    'port' => 5432,
    'database' => 'myapp',
    'username' => 'admin',
    'password' => getenv('RDS_PASSWORD'),
    'sslmode' => 'require',  // AWS RDS requiere SSL
    // Opcionalmente, verifica el certificado CA de AWS:
    // 'sslrootcert' => '/path/to/rds-ca-2019-root.pem',
    // 'sslmode' => 'verify-full',
];

$orm = new VersaORM\VersaORM($config);
```

Descarga el certificado CA de AWS RDS:
```bash
wget https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
```

### Heroku PostgreSQL

Para conectar a Heroku Postgres:

```php
<?php

// Heroku proporciona DATABASE_URL como variable de entorno
$databaseUrl = getenv('DATABASE_URL');
// Formato: postgres://user:password@host:port/database

// Parsear la URL
$url = parse_url($databaseUrl);

$config = [
    'driver' => 'pgsql',
    'host' => $url['host'],
    'port' => $url['port'] ?? 5432,
    'database' => ltrim($url['path'], '/'),
    'username' => $url['user'],
    'password' => $url['pass'],
    'sslmode' => 'require',  // Heroku requiere SSL
];

$orm = new VersaORM\VersaORM($config);
```

## Solución de Problemas

### Error: "SSL connection has been requested but SSL support is not available"

**Causa**: El driver PDO PostgreSQL no fue compilado con soporte SSL.

**Solución**: Recompila PHP con `--with-pgsql` y asegúrate de que PostgreSQL fue compilado con soporte SSL.

### Error: "SSL error: certificate verify failed"

**Causa**: El certificado del servidor no puede ser verificado.

**Soluciones**:
1. Proporciona el certificado CA correcto usando `sslrootcert`
2. Usa `sslmode=require` en lugar de `verify-ca` (menos seguro)
3. Verifica que el certificado no haya expirado

### Error: "server does not support SSL, but SSL was required"

**Causa**: El servidor PostgreSQL no está configurado para soportar SSL.

**Solución**: 
1. Configura SSL en el servidor PostgreSQL (`postgresql.conf`)
2. O usa `sslmode=disable` si no necesitas SSL (no recomendado en producción)

## Mejores Prácticas

### ✅ Recomendaciones

1. **Desarrollo**: Usa `sslmode=disable` para simplicidad
2. **Staging/QA**: Usa `sslmode=require` como mínimo
3. **Producción**: Usa `sslmode=verify-full` para máxima seguridad
4. **Nunca** incluyas contraseñas en el código fuente
5. Usa variables de entorno para todas las credenciales
6. Mantén los certificados fuera del código fuente
7. Rota certificados regularmente (antes de que expiren)

### ❌ Evitar

1. No uses `sslmode=disable` en producción
2. No compartas certificados privados en repositorios
3. No ignores errores de verificación de certificados
4. No uses certificados autofirmados en producción sin validación

## Verificar la Conexión SSL

Puedes verificar si la conexión usa SSL ejecutando:

```php
<?php

$result = $orm->exec("SELECT ssl_is_used() as ssl_enabled");
var_dump($result[0]['ssl_enabled']); // true si SSL está activo
```

O en PostgreSQL directamente:

```sql
SELECT * FROM pg_stat_ssl WHERE pid = pg_backend_pid();
```

## Referencias

- [Documentación oficial de PostgreSQL sobre SSL](https://www.postgresql.org/docs/current/libpq-ssl.html)
- [PDO PostgreSQL DSN](https://www.php.net/manual/en/ref.pdo-pgsql.connection.php)
- [Guía de SSL en AWS RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
