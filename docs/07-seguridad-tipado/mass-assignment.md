# Protección Mass Assignment

La protección contra Mass Assignment es una característica de seguridad crucial que previene la modificación no autorizada de campos sensibles cuando se asignan datos en lote a los modelos.

## ¿Qué es Mass Assignment?
gnment es la capacidad de asignar múltiples atributos a un modelo de una sola vez, típicamente desde datos de formularios o APIs. Sin protección adecuada, esto puede ser un riesgo de seguridad.

### Ejemplo del Problema

```php
// Datos del formulario (potencialmente maliciosos)
$userData = [
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com',
    'is_admin' => true,        // ¡Campo que no debería ser modificable!
    'salary' => 100000,        // ¡Campo sensible!
    'user_id' => 999           // ¡Intento de cambiar ID!
];

// Sin protección, todos los campos se asignarían
$user = VersaModel::dispense('users');
foreach ($userData as $key => $value) {
    $user->$key = $value;  // ¡Peligroso!
}
$user->store();
```

## Configuración de Protección

### Usando $fillable (Lista Blanca)

```php
class UserModel extends VersaModel {
    protected static $table = 'users';

    // Solo estos campos pueden ser asignados masivamente
    protected static $fillable = [
        'name',
        'email',
        'phone',
        'address',
        'birth_date'
    ];

    // Campos sensibles que NO están en $fillable:
    // - id
    // - is_admin
    // - salary
    // - created_at
    // - updated_at
}
```

### Usando $guarded (Lista Negra)

```php
class ProductModel extends VersaModel {
    protected static $table = 'products';

    // Estos campos NO pueden ser asignados masivamente
    protected static $guarded = [
        'id',
        'created_at',
        'updated_at',
        'internal_cost',
        'profit_margin'
    ];

    // Todos los demás campos SÍ pueden ser asignados:
    // - name, description, price, category_id, etc.
}
```

### Protección Total

```php
class AdminModel extends VersaModel {
    protected static $table = 'admins';

    // Proteger todos los campos (ninguno puede ser asignado masivamente)
    protected static $guarded = ['*'];

    // O alternativamente, $fillable vacío
    // protected static $fillable = [];
}
```

## Métodos de Asignación Segura

### Método fill()

```php
// Configuración del modelo
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];
}

// Uso seguro del método fill()
$userData = [
    'name' => 'Ana García',
    'email' => 'ana@example.com',
    'phone' => '555-1234',
    'is_admin' => true,        // ¡Será ignorado!
    'salary' => 50000          // ¡Será ignorado!
];

$user = new UserModel();
$user->fill($userData);        // Solo asigna campos en $fillable

echo $user->name;              // "Ana García"
echo $user->email;             // "ana@example.com"
echo $user->is_admin ?? 'null'; // null (no fue asignado)
```

### Método create()

```php
// Crear y guardar en una sola operación
$user = UserModel::create([
    'name' => 'Carlos López',
    'email' => 'carlos@example.com',
    'phone' => '555-5678',
    'is_admin' => true,        // ¡Será ignorado!
    'created_at' => '2020-01-01' // ¡Será ignorado!
]);

// Solo se asignan y guardan los campos permitidos
echo $user->name;              // "Carlos López"
echo $user->is_admin ?? 'null'; // null
```

### Método update()

```php
$user = UserModel::find(1);

// Actualización segura
$user->update([
    'name' => 'Carlos López Actualizado',
    'email' => 'carlos.nuevo@example.com',
    'is_admin' => true,        // ¡Será ignorado!
    'salary' => 75000          // ¡Será ignorado!
]);

// Solo se actualizan los campos permitidos
```

## Asignación Manual para Campos Protegidos

### Asignación Individual

```php
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];
}

$user = new UserModel();

// Asignación masiva segura
$user->fill([
    'name' => 'María González',
    'email' => 'maria@example.com',
    'is_admin' => true         // Ignorado
]);

// Asignación manual para campos sensibles (solo si tienes autorización)
if ($currentUser->hasPermission('manage_users')) {
    $user->is_admin = true;    // Asignación manual permitida
    $user->salary = 60000;     // Asignación manual permitida
}

$user->save();
```

### Método forceFill()

```php
// Para casos especiales donde necesitas saltarte la protección
$user = new UserModel();

// Asignación normal (respeta $fillable/$guarded)
$user->fill($userData);

// Asignación forzada (ignora protección) - ¡Usar con cuidado!
if ($currentUser->isSuperAdmin()) {
    $user->forceFill([
        'is_admin' => true,
        'salary' => 100000,
        'internal_notes' => 'Usuario especial'
    ]);
}
```

## Configuración Dinámica

### Modificar Protección en Tiempo de Ejecución

```php
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];

    // Permitir campos adicionales según el contexto
    public function allowAdminFields() {
        $this->addFillable(['is_admin', 'role', 'permissions']);
        return $this;
    }

    public function allowSalaryField() {
        $this->addFillable(['salary']);
        return $this;
    }
}

// Uso contextual
$user = new UserModel();

if ($currentUser->isHR()) {
    $user->allowSalaryField();
}

if ($currentUser->isSuperAdmin()) {
    $user->allowAdminFields();
}

$user->fill($requestData);
```

### Protección Basada en Roles

```php
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];

    public function getFillableForUser($currentUser) {
        $fillable = $this->getFillable();

        // Agregar campos según permisos
        if ($currentUser->hasPermission('edit_user_roles')) {
            $fillable[] = 'role';
        }

        if ($currentUser->hasPermission('edit_user_salary')) {
            $fillable[] = 'salary';
        }

        if ($currentUser->hasPermission('manage_admins')) {
            $fillable[] = 'is_admin';
        }

        return $fillable;
    }

    public function fillWithPermissions($data, $currentUser) {
        $allowedFields = $this->getFillableForUser($currentUser);
        $filteredData = array_intersect_key($data, array_flip($allowedFields));

        return $this->fill($filteredData);
    }
}
```

## Validación de Mass Assignment

### Detectar Intentos de Asignación No Autorizada

```php
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];

    public function fill($attributes) {
        // Detectar campos no permitidos
        $forbidden = array_diff(array_keys($attributes), $this->getFillable());

        if (!empty($forbidden)) {
            // Log del intento sospechoso
            error_log("Intento de mass assignment no autorizado: " . implode(', ', $forbidden));

            // Opcional: lanzar excepción
            if (config('app.strict_mass_assignment')) {
                throw new VersaORMException(
                    'Intento de asignar campos no permitidos: ' . implode(', ', $forbidden)
                );
            }
        }

        return parent::fill($attributes);
    }
}
```

### Auditoría de Cambios

```php
class AuditableModel extends VersaModel {
    public function fill($attributes) {
        $before = $this->toArray();

        parent::fill($attributes);

        $after = $this->toArray();
        $changes = array_diff_assoc($after, $before);

        // Registrar cambios para auditoría
        if (!empty($changes)) {
            $this->logChanges($changes);
        }

        return $this;
    }

    private function logChanges($changes) {
        $audit = $this->orm->dispense('audit_logs');
        $audit->model = get_class($this);
        $audit->model_id = $this->id;
        $audit->changes = json_encode($changes);
        $audit->user_id = auth()->id();
        $audit->created_at = date('Y-m-d H:i:s');

        $this->orm->store($audit);
    }
}
```

## Casos de Uso Avanzados

### Protección por Contexto

```php
class OrderModel extends VersaModel {
    protected static $fillable = ['customer_name', 'items', 'notes'];

    public function getFillableForStatus($status) {
        $base = $this->getFillable();

        switch ($status) {
            case 'draft':
                // En borrador, se puede modificar todo
                return array_merge($base, ['total', 'discount', 'tax']);

            case 'confirmed':
                // Confirmado, solo notas
                return ['notes'];

            case 'shipped':
                // Enviado, solo tracking
                return ['tracking_number', 'shipped_at'];

            case 'delivered':
                // Entregado, solo confirmación
                return ['delivered_at', 'delivery_notes'];

            default:
                return $base;
        }
    }

    public function updateForStatus($data, $status) {
        $allowedFields = $this->getFillableForStatus($status);
        $filteredData = array_intersect_key($data, array_flip($allowedFields));

        return $this->fill($filteredData);
    }
}
```

### Protección Temporal

```php
class EventModel extends VersaModel {
    protected static $fillable = ['title', 'description', 'location'];

    public function getFillableForDate() {
        $now = new DateTime();
        $eventDate = new DateTime($this->event_date);

        // Si el evento es en menos de 24 horas, solo permitir ciertos campos
        if ($eventDate->diff($now)->h < 24) {
            return ['notes', 'special_instructions'];
        }

        // Si el evento ya pasó, no permitir cambios
        if ($eventDate < $now) {
            return [];
        }

        // Evento futuro, permitir todos los campos
        return array_merge($this->getFillable(), ['event_date', 'capacity']);
    }
}
```

## Mejores Prácticas

### 1. Usar Lista Blanca ($fillable) por Defecto

```php
// ✅ Buena práctica: Definir explícitamente qué se puede asignar
class UserModel extends VersaModel {
    protected static $fillable = [
        'name', 'email', 'phone', 'address'
    ];
}

// ❌ Evitar: Usar solo $guarded puede ser menos seguro
class UserModel extends VersaModel {
    protected static $guarded = ['id']; // ¿Qué pasa si olvidas un campo sensible?
}
```

### 2. Nunca Exponer Campos Sensibles

```php
// ✅ Buena práctica: Mantener campos sensibles fuera de $fillable
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email', 'phone'];

    // Campos sensibles que NUNCA deben estar en $fillable:
    // - password (usar métodos específicos)
    // - is_admin (asignar manualmente con validación)
    // - api_token (generar automáticamente)
    // - email_verified_at (controlar por proceso)
}
```

### 3. Validar Permisos Antes de Asignación

```php
// ✅ Buena práctica: Verificar permisos antes de permitir asignación
public function updateUser($userId, $data, $currentUser) {
    $user = UserModel::find($userId);

    // Verificar que puede editar este usuario
    if (!$currentUser->canEdit($user)) {
        throw new UnauthorizedException('No tienes permisos para editar este usuario');
    }

    // Usar asignación segura
    $user->fill($data);
    $user->save();

    return $user;
}
```

### 4. Documentar Campos Sensibles

```php
class UserModel extends VersaModel {
    /**
     * Campos que pueden ser asignados masivamente
     *
     * NUNCA agregar a esta lista:
     * - id: Clave primaria, no debe modificarse
     * - is_admin: Campo sensible, requiere validación especial
     * - password: Usar setPassword() en su lugar
     * - api_token: Se genera automáticamente
     * - email_verified_at: Controlado por proceso de verificación
     */
    protected static $fillable = [
        'name',
        'email',
        'phone',
        'address',
        'birth_date'
    ];
}
```

## Errores Comunes

### Error: Permitir Campos Sensibles

```php
// ❌ Error común: Incluir campos sensibles en $fillable
class UserModel extends VersaModel {
    protected static $fillable = [
        'name', 'email', 'password', 'is_admin' // ¡Peligroso!
    ];
}

// ✅ Solución: Manejar campos sensibles por separado
class UserModel extends VersaModel {
    protected static $fillable = ['name', 'email'];

    public function setPassword($password) {
        $this->password = password_hash($password, PASSWORD_DEFAULT);
    }

    public function setAdminStatus($isAdmin, $currentUser) {
        if (!$currentUser->isSuperAdmin()) {
            throw new UnauthorizedException('Solo super admins pueden cambiar este campo');
        }
        $this->is_admin = $isAdmin;
    }
}
```

### Error: No Validar Entrada

```php
// ❌ Error común: Confiar en datos de entrada sin validar
$user->fill($_POST); // ¡Muy peligroso!

// ✅ Solución: Siempre validar y filtrar datos
$validatedData = $this->validateUserData($_POST);
$user->fill($validatedData);
```

La protección Mass Assignment es fundamental para la seguridad de tu aplicación. Siempre define explícitamente qué campos pueden ser asignados masivamente y maneja los campos sensibles con métodos específicos y validación de permisos.

## Siguiente Paso

Continúa con [Freeze Mode](freeze-mode.md) para aprender cómo proteger el esquema de tu base de datos contra modificaciones accidentales.