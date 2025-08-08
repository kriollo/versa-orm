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

    /**
     * Buscar por ID.
     */
    public static function find($id): ?self
    {
        return static::findOne('task_notes', (int) $id);
    }

    /**
     * Obtener todas las notas de una tarea.
     */
    public static function findByTask(int $taskId): array
    {
        return static::findAll('task_notes', 'task_id = ?', [$taskId]);
    }

    /**
     * Crear nueva nota.
     */
    public static function create(array $attributes): static
    {
        $errors = [];
        if (empty($attributes['content'])) {
            $errors[] = 'El contenido es requerido';
        }
        if (empty($attributes['task_id'])) {
            $errors[] = 'La tarea es requerida';
        }
        if (empty($attributes['user_id'])) {
            $errors[] = 'El usuario es requerido';
        }

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        $ormInstance = static::getGlobalORM();
        if (!$ormInstance) {
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
        }
        $note = new static('task_notes', $ormInstance);
        $note->fill($attributes);
        $note->store();
        return $note;
    }

    /**
     * Obtener tarea de la nota.
     */
    public function task(): ?Task
    {
        return Task::find($this->task_id);
    }

    /**
     * Obtener usuario que creó la nota.
     */
    public function user(): ?User
    {
        return User::find($this->user_id);
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
