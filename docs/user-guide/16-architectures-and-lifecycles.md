# Arquitecturas y Ciclo de Vida de Conexión

Esta guía muestra cómo integrar VersaORM en distintos estilos arquitectónicos y cómo gestionar el ciclo de vida de la conexión (creación, reutilización y liberación) en contextos request-based, CLI, workers persistentes y entornos sin PHP-FPM.

---
## Principios Clave
- **Inicialización Perezosa**: No se abre la conexión hasta el primer query.
- **Instancia Única por Request**: En MVC/HTTP, crea una sola instancia `VersaORM` y compártela.
- **Modelos Estáticos Opt-in**: `VersaModel::setORM($orm)` habilita métodos estáticos y accesores rápidos (`self::orm()`, `self::db()`).
- **Medición y Observabilidad**: Usa `$orm->metrics()` + `$orm->metricsReset()` para monitorear.
- **Liberación Explícita**: Para procesos largos o no-FPM, expón un método de desconexión manual.

---
## 1. MVC Tradicional (Front Controller)
```php
// public/index.php
require __DIR__.'/../vendor/autoload.php';
$config = require __DIR__.'/../config/db.php';
$orm = new VersaORM\VersaORM($config);
VersaORM\VersaModel::setORM($orm); // habilita métodos estáticos

// Router despacha
$response = $router->dispatch($_SERVER['REQUEST_URI']);
// (Opcional) liberar recursos al final
$orm = null; // GC liberará la conexión al terminar el request
```
Uso en un controlador:
```php
class UserController {
  public function index(): array {
    return VersaORM\VersaModel::db()->table('users')->get();
  }
}
```

---
## 2. MVC con Contenedor / Inversión de Control
```php
// bootstrap/container.php
$container->set(VersaORM\VersaORM::class, function() {
  $cfg = require __DIR__.'/../config/db.php';
  return new VersaORM\VersaORM($cfg);
});
$container->call([UserController::class, 'index']);
```
Controlador inyectado:
```php
class UserController {
  public function __construct(private VersaORM\VersaORM $orm) {}
  public function index(): array { return $this->orm->table('users')->get(); }
}
```
Modelos siguen usando `VersaModel::setORM()` si deseas métodos estáticos.

---
## 3. Frameworks Populares
| Framework | Integración Recomendada |
|----------|-------------------------|
| Laravel  | Service Provider que registre `VersaORM` como singleton; llamada a `VersaModel::setORM` en `boot()` |
| Symfony  | Definir servicio en `services.yaml`; autowire en controladores |
| Slim     | Añadir a `$app->getContainer()`; middleware inicial para setear ORM global |
| Mezzio   | ConfigProvider retornando factory para `VersaORM` |
| CodeIgniter / Laminas | Crear librería / factory y registrar |

Ejemplo (Laravel Service Provider simplificado):
```php
public function register(){
  $this->app->singleton(VersaORM\VersaORM::class, function(){
    return new VersaORM\VersaORM(config('database.versaorm'));
  });
}
public function boot(VersaORM\VersaORM $orm){
  VersaORM\VersaModel::setORM($orm);
}
```

---
## 4. Uso Estático vs Instanciado
| Escenario | Recomendación |
|-----------|---------------|
| Pequeñas utilidades / scripts | Métodos estáticos (`VersaModel::db()`) para brevedad |
| Apps medianas/grandes | Inyección de dependencia del objeto `VersaORM` |
| Tests unitarios | Instanciar manual y `VersaModel::setORM()` por testCase |

Ejemplo dual:
```php
// Estático
auth($email) { return User::db()->table('users')->where('email','=',$email)->first(); }
// Inyectado
function findUser(VersaORM\VersaORM $orm, string $email){ return $orm->table('users')->where('email','=',$email)->first(); }
```

---
## 5. Ciclo de Vida en Contextos Diferentes
### PHP-FPM / HTTP clásico
- Cada request termina y PHP destruye objetos => conexión cerrada automáticamente.
- No necesitas `disconnect()` manual.

### Swoole / RoadRunner / ReactPHP (Servidor Persistente)
- El proceso vive indefinidamente: NO recrees `VersaORM` por request.
- Crea una instancia global/shared y resetea métricas según necesites.
- Si requieres *reset de conexión* (timeouts, leaks) implementa `disconnect()`.

### CLI / Scripts Puntuales
```php
$orm = new VersaORM\VersaORM($cfg);
// operaciones
$orm = null; // o $orm->disconnect(); (si implementado)
```

### Workers / Jobs Largos (colas)
Patrón:
```php
$orm = new VersaORM\VersaORM($cfg);
$processed = 0;
while (jobAvailable()) {
  handleJob($orm, nextJob());
  if (++$processed % 500 === 0) { // reciclado periódico
    $orm->metricsReset();
    // opcional: $orm->disconnect();
  }
}
```

---
## 6. Implementar disconnect() (Opcional)
Si quieres liberación explícita agrega en `VersaORM`:
```php
public function disconnect(): void {
  if ($this->pdoEngine instanceof \VersaORM\SQL\PdoEngine) {
    $this->pdoEngine->forceDisconnect(); // método a crear
  }
}
```
En `PdoEngine` y `PdoConnection`:
```php
// PdoConnection.php
public function close(): void { $this->pdo = null; }
// PdoEngine.php
public function forceDisconnect(): void { $this->connector->close(); }
```
Esto permite liberar la conexión en procesos persistentes.

---
## 7. Patrones de Transacciones
```php
$orm->begin();
try {
  $orm->table('orders')->insert($data);
  $orm->commit();
} catch (\Throwable $e) {
  $orm->rollBack();
  throw $e;
}
```
(En un adaptador actual implementa begin/commit si expuestos; si no, crea wrappers en VersaORM que deleguen a PdoEngine).

---
## 8. Métricas y Observabilidad
```php
$orm->metricsReset();
$rows = $orm->table('users')->get();
print_r($orm->metrics());
```
Útil para tuning de caches y fast-path de hidratación.

---
## 9. Buenas Prácticas
- No crear una instancia por modelo; comparte una sola.
- Llamar a `VersaModel::setORM()` sólo una vez en bootstrap.
- Usar inyección en servicios para testear más fácilmente (mockear capa de datos).
- Resetear métricas antes de benchmarks.
- En servidores persistentes, monitorear memory footprint y reciclar si crece anormalmente.

---
## 10. Checklist de Integración Rápida
- [ ] Archivo de config listo
- [ ] Instanciado `VersaORM` en bootstrap
- [ ] `VersaModel::setORM($orm)` ejecutado
- [ ] Contenedor registra el ORM (si aplica)
- [ ] (Opcional) disconnect() implementado si servidor persistente
- [ ] Métricas visibles en entorno de staging

---
## 11. Próximos Pasos
- Añadir generadores de migraciones.
- Pool avanzado de conexiones (si múltiples DBs).
- OpenTelemetry spans para ejecución / hidratación.

---
¿Falta algún caso específico de tu arquitectura? Pide un ejemplo y lo añadimos.
