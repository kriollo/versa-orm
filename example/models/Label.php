<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Label
 * Gestiona etiquetas del sistema.
 */
class Label extends BaseModel
{
    protected string $table = 'labels';

    protected array $fillable = [
        'name',
        'color',
        'description',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'name'  => ['required', 'min:1', 'max:50'],
        'color' => ['required'],
    ];

    /** Atajo para buscar por ID (modelo tipado) compatible con BaseModel. */
    public static function find(int $id, string $pk = 'id'): ?static
    {
        return parent::find($id, $pk);
    }

    /** Crear etiqueta usando strong typing y mass-assignment seguro. */
    public static function create(array $attributes): static
    {
        if (!isset($attributes['color'])) {
            $attributes['color'] = static::generateRandomColor();
        }
        /** @var static $label */
        $label = static::dispense('labels');
        $label->fill($attributes);
        $label->store();
        return $label;
    }

    /**
     * Generar color aleatorio para etiqueta.
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
            '#f1c40f',
            '#e91e63',
            '#673ab7',
            '#00bcd4',
            '#4caf50',
        ];
        return $colors[array_rand($colors)];
    }

    /**
     * Obtener tareas con esta etiqueta.
     */
    public function tasks(): array
    {
        return static::orm()
            ->table('tasks', Task::class)
            ->join('task_labels', 'tasks.id', '=', 'task_labels.task_id')
            ->where('task_labels.label_id', '=', $this->id)
            ->orderBy('tasks.created_at', 'DESC')
            ->select(['tasks.*'])
            ->get();
    }

    /**
     * Contar tareas con esta etiqueta.
     */
    public function tasksCount(): int
    {
        $rows = static::orm()
            ->table('task_labels')
            ->select(['COUNT(*) AS count'])
            ->where('label_id', '=', $this->id)
            ->get();
        $row = $rows[0] ?? [];
        return (int)($row['count'] ?? 0);
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id'          => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'name'        => ['type' => 'string', 'max_length' => 50, 'nullable' => false],
            'color'       => ['type' => 'string', 'max_length' => 7, 'nullable' => false, 'default' => '#3498db'],
            'description' => ['type' => 'text', 'nullable' => true],
            'created_at'  => ['type' => 'datetime', 'nullable' => false],
            'updated_at'  => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
