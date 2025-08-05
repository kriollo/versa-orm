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
        return static::findOne('projects', (int) $id);
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
        $projectUser = static::dispense('project_users');
        $projectUser->project_id = $project->id;
        $projectUser->user_id = $attributes['owner_id'];
        $projectUser->store();

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
        $user = User::find($this->owner_id);
        return $user ? $user->export() : null;
    }

    /**
     * Obtener miembros del proyecto.
     */
    public function members(): array
    {
        // Por ahora mantener la consulta SQL directa hasta que podamos implementar el JOIN correctamente
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
        // Por ahora mantener la consulta SQL directa
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
            'SELECT 1 FROM project_users WHERE project_id = ? AND user_id = ? LIMIT 1',
            [$this->id, $userId]
        );

        if (empty($exists)) {
            // Usar VersaModel para crear la relación
            $projectUser = static::dispense('project_users');
            $projectUser->project_id = $this->id;
            $projectUser->user_id = $userId;
            $projectUser->store();
        }
    }

    /**
     * Remover miembro del proyecto.
     */
    public function removeMember(int $userId): void
    {
        // Buscar la relación y eliminarla
        $relations = static::getAll(
            'SELECT * FROM project_users WHERE project_id = ? AND user_id = ?',
            [$this->id, $userId]
        );

        foreach ($relations as $relation) {
            if (isset($relation['id'])) {
                $projectUser = static::load('project_users', $relation['id']);
                if ($projectUser) {
                    $projectUser->trash();
                }
            }
        }
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 100, 'nullable' => false],
            'description' => ['type' => 'text', 'nullable' => true],
            'color' => ['type' => 'string', 'max_length' => 7, 'nullable' => false, 'default' => '#3498db'],
            'owner_id' => ['type' => 'int', 'nullable' => false],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
