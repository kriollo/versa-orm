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
        'name' => ['required', 'min:2', 'max:100'],
        'owner_id' => ['required'],
    ];

    // ===================== Métodos CRUD de instancia =====================
    /** Crear nuevo proyecto (usa reglas y strong typing internos). */
    public function createOne(array $attributes): self
    {
        $this->ensureColor($attributes);
        $this->fill($attributes);
        $this->store();

        if (property_exists($this, 'owner_id') && $this->owner_id !== null) {
            $this->addMember((int) $this->owner_id);
        }

        return $this;
    }

    // ===================== Relaciones y consultas =====================

    /** Propietario del proyecto como array exportado. */
    public function owner(): ?array
    {
        if (!property_exists($this, 'owner_id') || $this->owner_id === null) {
            return null;
        }
        // Obtener usuario vía QueryBuilder usando el ORM inyectado en la instancia
        $user = $this->getOrm()->table('users', User::class)->where('id', '=', (int) $this->owner_id)->findOne();

        return $user?->export();
    }

    /** Miembros del proyecto (usuarios) vía tabla pivote project_users. */
    public function members(): array
    {
        return $this->getOrm()
            ->table('users', User::class)
            ->join('project_users', 'users.id', '=', 'project_users.user_id')
            ->where('project_users.project_id', '=', $this->id)
            ->get() // arrays ya casteados
        ;
    }

    /** Tareas asociadas al proyecto ordenadas por creación desc. */
    public function tasks(): array
    {
        return $this->getOrm()
            ->table('tasks', Task::class)
            ->where('project_id', '=', $this->id)
            ->orderBy('created_at', 'DESC')
            ->get()
        ;
    }

    /** Añadir miembro (inserta en project_users si no existe ya). */
    public function addMember(int $userId): void
    {
        $exists = $this->getOrm()->table('project_users')
            ->where('project_id', '=', $this->id)
            ->where('user_id', '=', $userId)
            ->exists()
        ;

        if ($exists) {
            return;
        }
        $pivot = $this->dispenseInstance('project_users');
        $pivot->project_id = $this->id;
        $pivot->user_id = $userId;
        $pivot->store();
    }

    /** Remover miembro del proyecto eliminando fila pivot. */
    public function removeMember(int $userId): void
    {
        $rows = $this->getOrm()->table('project_users')
            ->select(['id'])
            ->where('project_id', '=', $this->id)
            ->where('user_id', '=', $userId)
            ->get()
        ;

        foreach ($rows as $row) {
            if (!isset($row['id'])) {
                continue;
            }
            $pivot = $this->load('project_users', (int) $row['id']);
            $pivot?->trash();
        }
    }

    // ===================== Tipado fuerte / esquema =====================
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

    // ===================== Factores internos =====================
    // Helpers orm()/qb() heredados de BaseModel

    /** Genera color aleatorio si no viene definido. */
    private function ensureColor(array &$attributes): void
    {
        if (!isset($attributes['color'])) {
            $attributes['color'] = $this->generateRandomColor();
        }
    }

    // ===================== Utilidades internas =====================
    private function generateRandomColor(): string
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
