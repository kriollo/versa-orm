<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Project modernizado para usar QueryBuilder de VersaORM y evitar SQL crudo.
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
        'name'     => ['required', 'min:2', 'max:100'],
        'owner_id' => ['required'],
    ];

    /* ===================== Factores internos ===================== */
    // Helpers orm()/qb() heredados de BaseModel

    /** Genera color aleatorio si no viene definido. */
    private static function ensureColor(array &$attributes): void
    {
        if (!isset($attributes['color'])) {
            $attributes['color'] = static::generateRandomColor();
        }
    }

    /* ===================== Métodos CRUD estáticos ===================== */

    /** Buscar por ID. */
    public static function find($id): ?self
    {
        return static::findOne('projects', (int)$id);
    }

    /** Obtener todos los proyectos. */
    public static function all(): array
    {
        return static::findAll('projects');
    }

    /** Crear nuevo proyecto usando fill + store. */
    public static function create(array $attributes): static
    {
        static::ensureColor($attributes);

        $errors = [];
        if (empty($attributes['name'])) {
            $errors[] = 'El nombre es requerido';
        }
        if (empty($attributes['owner_id'])) {
            $errors[] = 'El propietario es requerido';
        }
        if ($errors) {
            throw new \InvalidArgumentException('Errores de validación: ' . implode(', ', $errors));
        }

        $project = new static('projects', static::orm());
        $project->fill($attributes);
        $project->store();

        // Añadir propietario como miembro (pivot project_users)
        static::addMemberToProject((int)$project->id, (int)$attributes['owner_id']);

        return $project;
    }

    /* ===================== Relaciones y consultas ===================== */

    /** Propietario del proyecto como array exportado. */
    public function owner(): ?array
    {
        $user = User::find($this->owner_id);
        return $user?->export();
    }

    /** Miembros del proyecto (usuarios) vía tabla pivote project_users. */
    public function members(): array
    {
        return static::orm()
            ->table('users')
            ->join('project_users', 'users.id', '=', 'project_users.user_id')
            ->where('project_users.project_id', '=', $this->id)
            ->get();
    }

    /** Tareas asociadas al proyecto ordenadas por creación desc. */
    public function tasks(): array
    {
        return static::orm()
            ->table('tasks')
            ->where('project_id', '=', $this->id)
            ->orderBy('created_at', 'DESC')
            ->get();
    }

    /** Añadir miembro (inserta en project_users si no existe ya). */
    public function addMember(int $userId): void
    {
        $exists = static::orm()->table('project_users')
            ->select(['id'])
            ->where('project_id', '=', $this->id)
            ->where('user_id', '=', $userId)
            ->limit(1)
            ->get();
        if (!$exists) {
            $pivot = static::dispense('project_users');
            $pivot->project_id = $this->id;
            $pivot->user_id    = $userId;
            $pivot->store();
        }
    }

    /** Remover miembro del proyecto eliminando fila pivot. */
    public function removeMember(int $userId): void
    {
        $rows = static::orm()->table('project_users')
            ->select(['id'])
            ->where('project_id', '=', $this->id)
            ->where('user_id', '=', $userId)
            ->get();
        foreach ($rows as $row) {
            if (isset($row['id'])) {
                $pivot = static::load('project_users', (int)$row['id']);
                $pivot?->trash();
            }
        }
    }

    /* ===================== Helpers pivot ===================== */
    private static function addMemberToProject(int $projectId, int $userId): void
    {
        $pivot = static::dispense('project_users');
        $pivot->project_id = $projectId;
        $pivot->user_id    = $userId;
        $pivot->store();
    }

    /* ===================== Tipado fuerte / esquema ===================== */
    public static function definePropertyTypes(): array
    {
        return [
            'id'          => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name'        => ['type' => 'string', 'max_length' => 100, 'nullable' => false],
            'description' => ['type' => 'text', 'nullable' => true],
            'color'       => ['type' => 'string', 'max_length' => 7, 'nullable' => false, 'default' => '#3498db'],
            'owner_id'    => ['type' => 'int', 'nullable' => false],
            'created_at'  => ['type' => 'datetime', 'nullable' => false],
            'updated_at'  => ['type' => 'datetime', 'nullable' => false],
        ];
    }

    /* ===================== Utilidades internas ===================== */
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
}
