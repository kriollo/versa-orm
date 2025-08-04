<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Project
 * Gestiona proyectos del sistema.
 */
class Project extends BaseModel
{
    protected string $table = 'projects';

    protected array $fillable = [
        'name',
        'description',
        'color',
        'owner_id',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'name' => ['required', 'min:2', 'max:100'],
        'owner_id' => ['required'],
    ];

    /**
     * Buscar por ID.
     */
    public static function find($id): ?self
    {
        return static::findOne('projects', (int)$id);
    }

    /**
     * Obtener todos los proyectos.
     */
    public static function all(): array
    {
        return static::findAll('projects');
    }

    /**
     * Crear nuevo proyecto.
     */
    public static function create(array $attributes): static
    {
        // Aplicar valores por defecto
        if (!isset($attributes['color'])) {
            $attributes['color'] = static::generateRandomColor();
        }

        // Validar antes de crear
        $errors = [];
        if (empty($attributes['name'])) {
            $errors[] = 'El nombre es requerido';
        }
        if (empty($attributes['owner_id'])) {
            $errors[] = 'El propietario es requerido';
        }

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        // Crear instancia correctamente con el nombre de tabla
        $ormInstance = static::getGlobalORM();
        if (!$ormInstance) {
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
        }
        $project = new static('projects', $ormInstance);
        $project->fill($attributes);
        $project->store();

        // Añadir el propietario como miembro del proyecto
        static::execSql(
            'INSERT INTO project_users (project_id, user_id) VALUES (?, ?)',
            [$project->id, $attributes['owner_id']]
        );

        return $project;
    }

    /**
     * Generar color aleatorio para proyecto.
     */
    private static function generateRandomColor(): string
    {
        $colors = [
            '#e74c3c',
            '#3498db',
            '#2ecc71',
            '#f39c12',
            '#9b59b6',
            '#1abc9c',
            '#e67e22',
            '#34495e',
            '#95a5a6',
            '#16a085',
        ];
        return $colors[array_rand($colors)];
    }

    /**
     * Obtener propietario del proyecto.
     */
    public function owner(): ?array
    {
        $result = static::getAll('SELECT * FROM users WHERE id = ?', [$this->owner_id]);
        return $result ? $result[0] : null;
    }

    /**
     * Obtener miembros del proyecto.
     */
    public function members(): array
    {
        return static::getAll(
            'SELECT u.* FROM users u
             INNER JOIN project_users pu ON u.id = pu.user_id
             WHERE pu.project_id = ?',
            [$this->id]
        );
    }

    /**
     * Obtener tareas del proyecto.
     */
    public function tasks(): array
    {
        return static::getAll(
            'SELECT * FROM tasks WHERE project_id = ? ORDER BY created_at DESC',
            [$this->id]
        );
    }

    /**
     * Añadir miembro al proyecto.
     */
    public function addMember(int $userId): void
    {
        // Verificar si ya es miembro
        $exists = static::getAll(
            'SELECT 1 FROM project_users WHERE project_id = ? AND user_id = ?',
            [$this->id, $userId]
        );

        if (empty($exists)) {
            static::execSql(
                'INSERT INTO project_users (project_id, user_id) VALUES (?, ?)',
                [$this->id, $userId]
            );
        }
    }

    /**
     * Remover miembro del proyecto.
     */
    public function removeMember(int $userId): void
    {
        static::execSql(
            'DELETE FROM project_users WHERE project_id = ? AND user_id = ?',
            [$this->id, $userId]
        );
    }
}
