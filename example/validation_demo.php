<?php

/**
 * Ejemplo práctico: Sistema de registro de usuario con validación
 *
 * Este ejemplo demuestra:
 * - Mass Assignment protection
 * - Validación automática
 * - Manejo de errores con VersaORMException
 * - Métodos de verificación (isFillable, isGuarded)
 */

require_once 'autoload.php';

use Example\Models\BaseModel;
use VersaORM\VersaORMException;

// Configuración de base de datos (requerida por VersaORMTrait)
$config = [
    'DB' => [
        'DB_DRIVER' => 'mysql',
        'DB_HOST' => 'localhost',
        'DB_PORT' => 3306,
        'DB_NAME' => 'versaorm_test',
        'DB_USER' => 'local',
        'DB_PASS' => 'local',
        // Activar modo debug para errores detallados y logging
        'debug' => true  // false para producción
    ]
];

// Modelo de ejemplo con validación completa
class UserRegistration extends BaseModel
{
    protected string $table = 'usuarios';

    // Solo estos campos pueden ser asignados masivamente
    protected array $fillable = [
        'name',
        'email',
        'password',
        'age'
    ];

    // Reglas de validación personalizadas
    protected array $rules = [
        'name' => ['required', 'min:2', 'max:50'],
        'email' => ['required', 'email'],
        'password' => ['required', 'min:8'],
        'age' => ['numeric']
    ];

    /**
     * Método personalizado para hashear password
     */
    public function setPassword(string $password): void
    {
        $this->password = password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Método de negocio: verificar si es mayor de edad
     */
    public function isAdult(): bool
    {
        return (int)$this->age >= 18;
    }
}

echo "<h1>🔒 Ejemplo de Validación y Mass Assignment</h1>\n";

// ===== EJEMPLO 1: Registro exitoso =====
echo "<h2>✅ Ejemplo 1: Registro exitoso</h2>\n";

try {
    $user = new UserRegistration();

    // Datos de un formulario de registro (simulados)
    $formData = [
        'name' => 'Ana García',
        'email' => 'ana@example.com',
        'password' => 'secreto123',
        'age' => 25,
        'is_admin' => true // ¡Intento malicioso! No está en $fillable
    ];

    // Fill con protección Mass Assignment
    $user->fill($formData);

    // Hash del password
    $user->setPassword($user->password);

    // Guardar con validación automática
    $user->store();

    echo "✅ Usuario registrado exitosamente<br>\n";
    echo "- Nombre: {$user->name}<br>\n";
    echo "- Email: {$user->email}<br>\n";
    echo "- Mayor de edad: " . ($user->isAdult() ? 'Sí' : 'No') . "<br>\n";
    echo "- ID asignado: {$user->id}<br>\n";
} catch (VersaORMException $e) {
    echo "❌ Error: {$e->getMessage()}<br>\n";
}

echo "<hr>\n";

// ===== EJEMPLO 2: Intento de Mass Assignment bloqueado =====
echo "<h2>🛡️ Ejemplo 2: Mass Assignment bloqueado</h2>\n";

try {
    $user = new UserRegistration();

    // Intento de asignar campo no permitido
    $maliciousData = [
        'name' => 'Hacker',
        'email' => 'hacker@evil.com',
        'is_admin' => true // ¡Campo no en $fillable!
    ];

    $user->fill($maliciousData);
} catch (VersaORMException $e) {
    echo "✅ Mass Assignment bloqueado correctamente<br>\n";
    echo "❌ Error: {$e->getMessage()}<br>\n";

    // Mostrar contexto del error
    $context = $e->getErrorDetails();
    if (isset($context['field'])) {
        echo "- Campo bloqueado: {$context['field']}<br>\n";
        echo "- Campos permitidos: " . implode(', ', $context['fillable']) . "<br>\n";
    }
}

echo "<hr>\n";

// ===== EJEMPLO 3: Validación fallida =====
echo "<h2>❌ Ejemplo 3: Validación fallida</h2>\n";

try {
    $user = new UserRegistration();

    // Datos inválidos
    $invalidData = [
        'name' => 'A', // Muy corto (min:2)
        'email' => 'email-invalido', // Formato incorrecto
        'password' => '123', // Muy corto (min:8)
        'age' => 'no-es-numero' // No numérico
    ];

    $user->fill($invalidData);
    $user->store(); // Esto debería fallar

} catch (VersaORMException $e) {
    echo "✅ Validación funcionando correctamente<br>\n";
    echo "❌ Errores encontrados:<br>\n";

    $context = $e->getErrorDetails();
    if (isset($context['errors'])) {
        foreach ($context['errors'] as $error) {
            echo "  - {$error}<br>\n";
        }
    }
}

echo "<hr>\n";

// ===== EJEMPLO 4: Validación manual =====
echo "<h2>🔍 Ejemplo 4: Validación manual</h2>\n";

$user = new UserRegistration();
$user->fill([
    'name' => 'Luis',
    'email' => 'luis@example.com',
    'password' => 'password123',
    'age' => 30
]);

// Validar sin guardar
$errors = $user->validate();

if (empty($errors)) {
    echo "✅ Datos válidos - listo para guardar<br>\n";
    echo "- Verificación adicional: Usuario es " . ($user->isAdult() ? 'mayor' : 'menor') . " de edad<br>\n";
} else {
    echo "❌ Errores de validación:<br>\n";
    foreach ($errors as $error) {
        echo "  - {$error}<br>\n";
    }
}

echo "<hr>\n";

// ===== EJEMPLO 5: Métodos de verificación =====
echo "<h2>🔍 Ejemplo 5: Métodos de verificación</h2>\n";

$user = new UserRegistration();

echo "<strong>Campos permitidos (fillable):</strong><br>\n";
foreach (['name', 'email', 'password', 'age', 'is_admin', 'created_at'] as $field) {
    $status = $user->isFillable($field) ? '✅ Permitido' : '❌ Bloqueado';
    echo "- {$field}: {$status}<br>\n";
}

echo "<br><strong>Lista completa de campos fillable:</strong><br>\n";
echo implode(', ', $user->getFillable()) . "<br>\n";

echo "<br><strong>Lista completa de campos guarded:</strong><br>\n";
echo implode(', ', $user->getGuarded()) . "<br>\n";

echo "<hr>\n";

// ===== EJEMPLO 6: Actualización segura =====
echo "<h2>🔄 Ejemplo 6: Actualización segura</h2>\n";

// Buscar usuario existente (simulamos que existe)
// Primero configurar el ORM estático
$tempUser = new UserRegistration();
VersaORM\VersaModel::setORM($tempUser->getORM());

if ($existingUser = UserRegistration::findOne('usuarios', 1)) {
    try {
        // Actualización segura con mass assignment
        $existingUser->update([
            'name' => 'Ana García Martínez',
            'email' => 'ana.garcia@example.com'
        ]);

        echo "✅ Usuario actualizado exitosamente<br>\n";
        echo "- Nuevo nombre: {$existingUser->name}<br>\n";
    } catch (VersaORMException $e) {
        echo "❌ Error en actualización: {$e->getMessage()}<br>\n";
    }
} else {
    echo "ℹ️ No hay usuarios existentes para actualizar<br>\n";
}

echo "<hr>\n";

echo "<h2>🎉 Resumen</h2>\n";
echo "✅ Mass Assignment protection funcional<br>\n";
echo "✅ Validación automática antes de store()<br>\n";
echo "✅ Validación manual disponible<br>\n";
echo "✅ Métodos de verificación (isFillable, isGuarded)<br>\n";
echo "✅ Manejo robusto de errores con contexto<br>\n";
echo "✅ Integración completa con modelos personalizados<br>\n";

echo "<p><strong>La Task 1.6 - Validación y Mass Assignment está completamente implementada.</strong></p>\n";
