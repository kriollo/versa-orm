<?php

declare(strict_types=1);

namespace App\Models;

/**
 * Modelo Note
 * Gestiona notas de las tareas.
 */
class Note extends BaseModel
{
    protected string $table = 'task_notes';

    protected array $fillable = [
        'content',
        'task_id',
        'user_id',
    ];

    protected array $guarded = [];

    protected array $rules = [
        'content' => ['required', 'min:3'],
        'task_id' => ['required'],
        'user_id' => ['required'],
    ];

    /** Buscar por ID (modelo tipado) compatible con BaseModel. */
    public static function find(int $id, string $pk = 'id'): ?static
    {
        return parent::find($id, $pk);
    }

    /** Listar notas por task_id como arrays exportados. */
    public static function findByTask(int $taskId): array
    {
        return static::orm()->table('task_notes', static::class)
            ->where('task_id', '=', $taskId)
            ->orderBy('created_at', 'DESC')
            ->get();
    }

    /** Crear nueva nota usando strong typing. */
    public static function create(array $attributes): static
    {
        /** @var static $note */
        $note = static::dispense('task_notes');
        $note->fill($attributes);
        $note->store();
        return $note;
    }

    /**
     * Obtener tarea de la nota.
     */
    public function task(): ?array
    {
        $task = Task::findOne('tasks', (int)$this->task_id);
        return $task?->export();
    }

    /**
     * Obtener usuario que creó la nota.
     */
    public function user(): ?array
    {
        $user = User::findOne('users', (int)$this->user_id);
        return $user?->export();
    }

    /**
     * Definir tipos de propiedades para validación de esquema y tipado fuerte.
     */
    public static function definePropertyTypes(): array
    {
        return [
            'id'         => ['type' => 'int', 'nullable' => false, 'auto_increment' => true],
            'content'    => ['type' => 'text', 'nullable' => false],
            'task_id'    => ['type' => 'int', 'nullable' => false],
            'user_id'    => ['type' => 'int', 'nullable' => false],
            'created_at' => ['type' => 'datetime', 'nullable' => false],
            'updated_at' => ['type' => 'datetime', 'nullable' => false],
        ];
    }
}
