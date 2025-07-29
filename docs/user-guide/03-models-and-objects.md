# Guía de Modelos y Objetos

Si bien el [Uso Básico](01-basic-usage.md) con `VersaModel` genérico es rápido, el verdadero poder de un ORM se desbloquea cuando creas tus propios modelos de aplicación. Un modelo es una clase PHP que representa una tabla específica de tu base de datos (p. ej., una clase `User` para tu tabla `users`).

Crear modelos personalizados te permite:

-   **Encapsular lógica de negocio:** Añadir métodos directamente relacionados con tus datos (p. ej., `User->sendWelcomeEmail()`).
-   **Definir "scopes" de consulta reutilizables:** Crear métodos estáticos para consultas comunes (p. ej., `Post::published()`).
-   **Añadir validación personalizada:** Validar los datos antes de guardarlos en la base de datos.
-   **Gestionar relaciones** entre tablas de forma más limpia.

## Creando tu Primer Modelo

La forma más sencilla de crear un modelo es extender la clase `Example\Models\BaseModel` que se encuentra en la carpeta de ejemplos, o crear una propia que utilice el `VersaORM\Traits\VersaORMTrait`.

Aquí tienes un ejemplo de un modelo `User` para una tabla `users`.

```php
// en models/User.php
namespace App\Models;

use Example\Models\BaseModel; // O tu propio modelo base

class User extends BaseModel
{
    /**
     * El nombre de la tabla asociada con el modelo.
     * @var string
     */
    protected string $table = 'users';

    /**
     * Los atributos que se pueden asignar masivamente.
     * @var array
     */
    protected array $fillable = [
        'name',
        'email',
        'password',
        'status'
    ];

    /**
     * Lógica de validación personalizada.
     */
    public function validate(): array
    {
        $errors = [];
        if (empty($this->name)) {
            $errors['name'] = 'El nombre es requerido.';
        }
        if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'El formato del email no es válido.';
        }
        return $errors;
    }

    /**
     * Un método de ejemplo para la lógica de negocio.
     */
    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * Un "scope" de consulta para obtener solo los usuarios activos.
     */
    public static function findActive(): array
    {
        $instance = new static();
        return $instance->db->table($instance->table)
            ->where('status', '=', 'active')
            ->findAll();
    }
}
```

### Uso del Modelo Personalizado

Ahora puedes usar tu modelo `User` de forma mucho más expresiva:

```php
// Crear un nuevo usuario
$user = new User();
$user->name = 'Marta';
$user->email = 'marta@example.com';
$user->store(); // El método store() viene del BaseModel

// Encontrar un usuario y usar sus métodos
$foundUser = User::find(1);
if ($foundUser->isActive()) {
    echo $foundUser->name . " está activo.";
}

// Usar el scope de consulta personalizado
$activeUsers = User::findActive();
```

## El `VersaORMTrait`

El `VersaORM\Traits\VersaORMTrait` es un atajo útil. Cuando lo incluyes en una clase, le proporciona automáticamente:

-   Una propiedad `$this->db` que contiene la instancia de `VersaORM`.
-   Un método `connectORM()` para inicializar la conexión.
-   Un método `getORM()` para obtener la instancia.

El `BaseModel` del ejemplo ya usa este trait, por lo que al extenderlo, tus modelos hijos heredan esta funcionalidad.

---

## Arrays vs. Objetos: ¿Cuándo Usar Cada Uno?

VersaORM te da la flexibilidad de obtener resultados como **arrays puros** o como **objetos de modelo**. La elección depende de tus necesidades.

### Cuándo usar **Arrays**

Usa arrays cuando la **velocidad y el bajo consumo de memoria** son tu máxima prioridad y no necesitas lógica de negocio asociada a los resultados.

**Métodos:**
-   `$orm->table('...')->getAll()`
-   `$orm->table('...')->firstArray()`
-   `$orm->exec('SELECT ...')`

**Casos de uso ideales:**

1.  **Respuestas de API JSON:** Es el caso de uso más común. Simplemente obtienes los datos y los codificas en JSON. No hay necesidad de objetos.

    ```php
    $products = $orm->table('products')->getAll();
    header('Content-Type: application/json');
    echo json_encode($products);
    ```

2.  **Reportes y Agregados:** Cuando realizas consultas complejas con `GROUP BY`, `SUM`, `COUNT`, etc., los resultados no mapean a un modelo único, por lo que un array es más adecuado.

    ```php
    $salesReport = $orm->table('orders')
        ->select(['DATE(created_at) as date', 'SUM(total) as daily_total'])
        ->groupBy('date')
        ->getAll();
    ```

3.  **Listas Simples:** Para poblar un `<select>` en HTML o cualquier lista simple donde solo necesitas un par de campos.

### Cuándo usar **Objetos**

Usa objetos (`VersaModel` o tus modelos personalizados) cuando trabajas con la **lógica de negocio** de tu aplicación.

**Métodos:**
-   `$orm->table('...')->findAll()`
-   `$orm->table('...')->findOne()`
-   `User::find(1)` (en tu modelo personalizado)

**Casos de uso ideales:**

1.  **Manipulación de Entidades:** Cuando necesitas cargar un registro, cambiar algunos de sus datos y guardarlo de nuevo.

    ```php
    $user = User::find(1);
    $user->last_login = date('Y-m-d H:i:s');
    $user->store(); // Mucho más limpio que un UPDATE manual
    ```

2.  **Lógica de Negocio Compleja:** Cuando necesitas llamar a métodos que viven en el modelo.

    ```php
    $order = Order::find(123);
    if ($order->isShippable()) {
        $order->ship(); // El método ship() contiene la lógica de envío
    }
    ```

3.  **Código Limpio y Expresivo:** Usar objetos hace que tu código sea más legible y fácil de mantener. `if ($user->isActive())` es mucho más claro que `if ($user['status'] == 1)`.

### Resumen de la Comparativa

| Característica | Arrays (`getAll`)                               | Objetos (`findAll`)                                |
| :--------------- | :---------------------------------------------- | :------------------------------------------------- |
| **Rendimiento**  | **Más alto.** Mínima sobrecarga.                | Ligeramente menor debido a la creación de objetos. |
| **Memoria**      | **Menor consumo.**                               | Mayor consumo por instancia de objeto.             |
| **Uso**          | Datos crudos, APIs, reportes.                   | Lógica de negocio, manipulación de registros.      |
| **Expresividad** | Bajo. `echo $user['name'];`                     | **Alto.** `echo $user->name;` `if ($user->isActive())` |
| **Mantenimiento**| Menor. Cambios en la DB rompen el código.       | **Mayor.** La lógica está encapsulada en el modelo. |

## Siguientes Pasos

Para los desarrolladores que deseen ir un paso más allá, la siguiente sección cubre el uso de la **[Herramienta de Línea de Comandos (CLI)](04-cli-tool.md)** que viene con VersaORM.
