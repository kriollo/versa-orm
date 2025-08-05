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
        'name' => ['required', 'min:1', 'max:50'],
        'color' => ['required'],
    ];

    /**
     * Buscar por ID.
     */
    public static function find($id): ?self
    {
        return static::findOne('labels', (int) $id);
    }

    /**
     * Obtener todas las etiquetas.
     */
    public static function all(): array
    {
        return static::findAll('labels');
    }

    /**
     * Crear nueva etiqueta.
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

        if (!empty($errors)) {
            throw new \Exception('Errores de validación: ' . implode(', ', $errors));
        }

        // Crear instancia correctamente con el nombre de tabla
        $ormInstance = static::getGlobalORM();
        if (!$ormInstance) {
            throw new \Exception('No ORM instance available. Call Model::setORM() first.');
        }
        $label = new static('labels', $ormInstance);
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
        return static::getAll(
            'SELECT t.* FROM tasks t
             INNER JOIN task_labels tl ON t.id = tl.task_id
             WHERE tl.label_id = ?
             ORDER BY t.created_at DESC',
            [$this->id]
        );
    }

    /**
     * Contar tareas con esta etiqueta.
     */
    public function tasksCount(): int
    {
        $result = static::getRow(
            'SELECT COUNT(*) as count FROM task_labels WHERE label_id = ?',
            [$this->id]
        );
        return (int) ($result['count'] ?? 0);
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
}
