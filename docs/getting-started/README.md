# Primeros Pasos

Sigue estos pasos para tener VersaORM funcionando en minutos.

1) Instala la librería
- [Instalación](installation.md)

2) Configura la conexión
- [Configuración](configuration.md)

3) Prueba tu primera consulta
```php
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM([
  'driver' => 'mysql',
  'host' => 'localhost',
  'database' => 'mi_app',
  'username' => 'usuario',
  'password' => 'password',
  'charset' => 'utf8mb4',
]);

VersaModel::setORM($orm);

$users = $orm->table('users')
  ->where('status', '=', 'active')
  ->orderBy('created_at', 'desc')
  ->getAll();
```

¿Listo para profundizar? Pasa a la [Guía de Uso](../user-guide/README.md).
