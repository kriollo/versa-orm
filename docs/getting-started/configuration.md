# Configuración

Una vez que hayas instalado VersaORM, el siguiente paso es configurar la conexión a tu base de datos. VersaORM necesita saber cómo conectarse a tu servidor de base de datos para poder ejecutar consultas.

## Creando la Instancia de VersaORM

La configuración se pasa como un array al constructor de la clase `VersaORM\VersaORM`.

Aquí tienes un ejemplo de cómo configurar una conexión a una base de datos MySQL:

```php
use VersaORM\VersaORM;

$config = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'port'     => 3306,
    'database' => 'mi_base_de_datos',
    'username' => 'mi_usuario',
    'password' => 'mi_contraseña',
    'charset'  => 'utf8mb4',
    'debug'    => true, // Opcional: actívalo para obtener errores detallados
];

$orm = new VersaORM($config);
```

### Parámetros de Configuración

- `driver` (obligatorio): El tipo de base de datos. Valores soportados: `mysql`, `pgsql` (para PostgreSQL), `sqlite`.
- `host` (obligatorio): La dirección del servidor de la base de datos (p. ej., `localhost` o una IP).
- `port` (opcional): El puerto de la base de datos. Por defecto: `3306` para MySQL, `5432` para PostgreSQL.
- `database` (obligatorio): El nombre de la base de datos a la que te quieres conectar.
- `username` (obligatorio): El nombre de usuario para acceder a la base de datos.
- `password` (obligatorio): La contraseña del usuario.
- `charset` (opcional): El juego de caracteres para la conexión. Se recomienda `utf8mb4` para MySQL.
- `debug` (opcional): Si se establece a `true`, VersaORM proporcionará mensajes de error mucho más detallados, incluyendo la consulta SQL que falló. **Se recomienda `false` en producción.**

## Configuración para PostgreSQL

```php
$config = [
    'driver'   => 'pgsql',
    'host'     => 'localhost',
    'port'     => 5432,
    'database' => 'mi_base_de_datos_pg',
    'username' => 'postgres',
    'password' => 'mi_contraseña_segura',
    'charset'  => 'utf8',
];

$orm = new VersaORM($config);
```

## Configuración para SQLite

Para SQLite, la configuración es más sencilla. Solo necesitas especificar el `driver` y la ruta al archivo de la base de datos en el parámetro `database`.

```php
$config = [
    'driver'   => 'sqlite',
    'database' => '/ruta/a/mi/base_de_datos.sqlite',
];

$orm = new VersaORM($config);
```

## Configuración Global para Modelos (Recomendado)

Para poder usar los métodos estáticos de `VersaModel` (como `find()`, `create()`, etc.), necesitas registrar la instancia del ORM de forma global. Esto se hace con el método `VersaModel::setORM()`.

Este es el flujo de trabajo recomendado:

```php
use VersaORM\VersaORM;
use VersaORM\VersaModel;

// 1. Configura y crea la instancia del ORM
$config = [
    'driver'   => 'mysql',
    'host'     => 'localhost',
    'database' => 'mi_base_de_datos',
    'username' => 'mi_usuario',
    'password' => 'mi_contraseña',
];

$orm = new VersaORM($config);

// 2. Registra la instancia del ORM para los modelos
VersaModel::setORM($orm);

// ¡Listo! Ahora puedes usar los modelos en cualquier parte de tu aplicación
$user = VersaModel::load('users', 1);
```

## Siguientes Pasos

Ahora que has configurado la conexión, estás listo para empezar a interactuar con tu base de datos. Dirígete a la sección de **[Uso Básico](../user-guide/01-basic-usage.md)** para aprender a realizar operaciones CRUD.
