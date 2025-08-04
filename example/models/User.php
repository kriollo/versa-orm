<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo User
 * Gestiona usuarios del sistema.
 */
class User extends BaseModel
{
    protected string $table = 'users';

    protected array $fillable = [
        'name',
        'email',
        'avatar_color',
        'active',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'name' => ['required', 'min:2', 'max:100'],
        'email' => ['required', 'email', 'max:150'],
    ];

    /**
     * Buscar por ID.
     */
    public static function find($id): ?self
    {
        return static::findOne('users', (int)$id);
    }

    /**
     * Obtener todos los usuarios.
     */
    public static function all(): array
    {
        return static::findAll('users');
    }

    /**
     * Crear nuevo usuario.
     */
    public static function create(array $attributes): static
    {
        // Aplicar valores por defecto
        if (!isset($attributes['avatar_color'])) {
            $attributes['avatar_color'] = static::generateRandomColor();
        }

        // Validar antes de crear
        $errors = [];
        if (empty($attributes['name'])) {
            $errors[] = 'El nombre es requerido';
        }
        if (empty($attributes['email'])) {
            $errors[] = 'El email es requerido';
        }
        if (!filter_var($attributes['email'], FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email inválido';
        }

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        // Crear instancia correctamente con el nombre de tabla
        $ormInstance = static::getGlobalORM();
        if (!$ormInstance) {
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
        }
        $user = new static('users', $ormInstance);
        $user->fill($attributes);
        $user->store();
        return $user;
    }

    /**
     * Generar color aleatorio para avatar.
     */
    private static function generateRandomColor(): string
    {
        $colors = [
            '#ff6b6b',
            '#4ecdc4',
            '#45b7d1',
            '#96ceb4',
            '#ffeaa7',
            '#dda0dd',
            '#98d8c8',
            '#fdcb6e',
            '#6c5ce7',
            '#fd79a8',
            '#e17055',
            '#00b894',
            '#0984e3',
            '#a29bfe',
            '#fd79a8',
        ];
        return $colors[array_rand($colors)];
    }

    /**
     * Obtener proyectos del usuario.
     */
    public function projects(): array
    {
        return static::getAll(
            'SELECT p.* FROM projects p
             INNER JOIN project_users pu ON p.id = pu.project_id
             WHERE pu.user_id = ?',
            [$this->id]
        );
    }

    /**
     * Obtener tareas asignadas al usuario.
     */
    public function tasks(): array
    {
        return static::getAll(
            'SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC',
            [$this->id]
        );
    }
}
