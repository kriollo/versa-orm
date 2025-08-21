<?php

declare(strict_types=1);

namespace App\Models;

use App\BaseModel;

/**
 * Modelo Label
 * Gestiona etiquetas del sistema.
 */
class Label extends BaseModel
{
    protected string $table = 'labels';

    /** Campos asignables en masa */
    protected array $fillable = [
        'name',
        'color',
        'description',
    ];

    /** Campos protegidos contra asignación en masa */
    protected array $guarded = [];

    protected array $rules = [
        'name' => ['required', 'min:1', 'max:50'],
        'color' => ['required'],
    ];

    /** Obtener el conteo total de etiquetas. */
    public static function countAll(): int
    {
        return self::queryTable()->count();
    }

    /** Relación N:M: tareas con esta etiqueta (BelongsToMany). */
    public function tasksRelation(): \VersaORM\Relations\BelongsToMany
    {
        return $this->belongsToMany(
            Task::class,
            'task_labels',
            'label_id',
            'task_id',
            'id',
            'id',
        );
    }

    /** Adjuntar tarea a la etiqueta. */
    public function attachTask(int $taskId): void
    {
        $this->tasksRelation()->attach($taskId);
    }

    /** Separar tarea de la etiqueta. */
    public function detachTask(int $taskId): void
    {
        $this->tasksRelation()->detach($taskId);
    }

    /** Sincronizar tareas de la etiqueta. */
    public function syncTasks(array $taskIds): array
    {
        return $this->tasksRelation()->sync($taskIds);
    }

    /** Recargar la etiqueta desde la base de datos (fresh). */
    public function fresh(string $primaryKey = 'id'): static
    {
        return parent::fresh($primaryKey);
    }

    /** Crear etiqueta (instancia) usando strong typing y mass-assignment seguro. */
    public function createOne(array $attributes): self
    {
        if (!isset($attributes['color'])) {
            $attributes['color'] = $this->generateRandomColor();
        }
        $this->fill($attributes);
        $this->store();

        return $this;
    }

    /**
     * Obtener tareas con esta etiqueta.
     */
    public function tasks(): array
    {
        return $this->getOrm()
            ->table('tasks', Task::class)
            ->join('task_labels', 'tasks.id', '=', 'task_labels.task_id')
            ->where('task_labels.label_id', '=', $this->id)
            ->orderBy('tasks.created_at', 'DESC')
            ->select(['tasks.*'])
            ->get()
        ;
    }

    /**
     * Contar tareas con esta etiqueta.
     */
    public function tasksCount(): int
    {
        $rows = $this->getOrm()
            ->table('task_labels')
            ->select(['COUNT(*) AS count'])
            ->where('label_id', '=', $this->id)
            ->get();
        $row = $rows[0] ?? [];

        return (int) ($row['count'] ?? 0);
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id' => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name' => ['type' => 'string', 'max_length' => 50, 'nullable' => false],
            'color' => ['type' => 'string', 'max_length' => 7, 'nullable' => false, 'default' => '#3498db'],
            'description' => ['type' => 'text', 'nullable' => true],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }

    /**
     * Generar color aleatorio para etiqueta.
     */
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
            '#f1c40f',
            '#e91e63',
            '#673ab7',
            '#00bcd4',
            '#4caf50',
        ];

        return $colors[array_rand($colors)];
    }
}
