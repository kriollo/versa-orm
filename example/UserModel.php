<?php

declare(strict_types=1);

namespace App\Models;

use VersaORM\VersaORMException;

use function count;
use function strlen;

/**
 * UserModel - Ejemplo de modelo específico con manejo de errores.
 */
class UserModel extends BaseModel
{
    protected string $table = 'users';

    protected array $fillable = [
        'name',
        'email',
        'password',
        'status',
        'created_at',
        'updated_at',
    ];

    protected array $guarded = [
        'id',
        'password_reset_token',
        'email_verified_at',
    ];

    /**
     * Crear usuario con validación completa.
     */
    public static function createUser(array $userData): array
    {
        $user = new static($userData);

        // Validar datos antes de guardar
        $validationErrors = $user->validateModel();

        if (!empty($validationErrors)) {
            return [
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validationErrors,
            ];
        }

        // Hash password si está presente
        if (isset($userData['password'])) {
            $user->setAttribute('password', password_hash($userData['password'], PASSWORD_DEFAULT));
        }

        // Intentar guardar
        $user->safeSave();

        return $user->createApiResponse();
    }

    /**
     * Actualizar usuario con validación.
     */
    public function updateUser(array $userData): array
    {
        // Hash password si está presente
        if (isset($userData['password'])) {
            $userData['password'] = password_hash($userData['password'], PASSWORD_DEFAULT);
        }

        $this->safeUpdate($userData);

        return $this->updateApiResponse();
    }

    /**
     * Buscar usuario por email con manejo de errores.
     */
    public static function findByEmail(string $email): ?static
    {
        try {
            $users = static::findAllWithErrorHandling(['email' => $email]);

            return empty($users) ? null : $users[0];
        } catch (VersaORMException $e) {
            ErrorHandler::handleException($e, [
                'model_class' => static::class,
                'operation' => 'findByEmail',
                'email' => $email,
            ]);

            return null;
        }
    }

    /**
     * Verificar si el email ya existe.
     */
    public function emailExists(string $email): bool
    {
        $existingUser = static::findByEmail($email);

        return $existingUser !== null;
    }

    /**
     * Activar usuario.
     */
    public function activate(): array
    {
        return $this->executeWithLogging('activate', function (): array {
            $this->setAttribute('status', 'active');
            $this->setAttribute('email_verified_at', date('Y-m-d H:i:s'));

            return $this->save();
        });
    }

    /**
     * Desactivar usuario.
     */
    public function deactivate(): array
    {
        return $this->executeWithLogging('deactivate', function (): array {
            $this->setAttribute('status', 'inactive');

            return $this->save();
        });
    }

    /**
     * Obtener estadísticas específicas del modelo User.
     */
    public static function getUserStats(): array
    {
        $baseStats = static::getPerformanceStats();

        try {
            // Contar usuarios activos
            $activeUsers = static::findAllWithErrorHandling(['status' => 'active']);
            $inactiveUsers = static::findAllWithErrorHandling(['status' => 'inactive']);

            $baseStats['user_stats'] = [
                'active_users' => count($activeUsers),
                'inactive_users' => count($inactiveUsers),
                'total_users' => count($activeUsers) + count($inactiveUsers),
            ];
        } catch (VersaORMException $e) {
            $baseStats['user_stats'] = [
                'error' => 'Could not retrieve user statistics',
                'error_code' => $e->getErrorCode(),
            ];
        }

        return $baseStats;
    }

    /**
     * Validaciones personalizadas para el modelo User.
     */
    protected function customValidation(): array
    {
        $errors = [];

        // Validar email
        if (isset($this->attributes['email']) && !filter_var($this->attributes['email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email format';
        }

        // Validar nombre
        if (isset($this->attributes['name']) && strlen($this->attributes['name']) < 2) {
            $errors[] = 'Name must be at least 2 characters long';
        }

        // Validar password (si está presente)
        if (isset($this->attributes['password']) && strlen($this->attributes['password']) < 8) {
            $errors[] = 'Password must be at least 8 characters long';
        }

        return $errors;
    }
}
