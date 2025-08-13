<?php

declare(strict_types=1);

namespace App\Models;

use DateTime;
use VersaORM\Interfaces\TypedModelInterface;
use VersaORM\Traits\HasStrongTyping;
use VersaORM\VersaModel;

use function count;
use function is_array;
use function sprintf;

/**
 * Modelo de ejemplo con tipado fuerte PHP 8+
 * Demuestra el uso completo del sistema de tipos avanzados.
 */
class TypedProduct extends VersaModel implements TypedModelInterface
{
    use HasStrongTyping;

    // Propiedades con tipado en PHPDoc (compatibilidad amplia)
    /** @var int */
    public $id;

    /** @var string */
    public $name;

    /** @var string */
    public $description;

    /** @var float */
    public $price;

    /** @var bool */
    public $active;

    /** @var DateTime|null */
    public $created_at;

    /** @var DateTime|null */
    public $updated_at;

    // Tipos avanzados con PHPDoc
    /** @var string UUID v4 */
    public $uuid;

    /** @var array JSON metadata */
    public $metadata;

    /** @var array SET de tags */
    public $tags;

    /** @var string ENUM status */
    public $status;

    /** @var string|null BLOB como base64 */
    public $image_blob;

    /** @var array PostgreSQL array */
    public $specifications;

    protected string $table = 'products';

    protected array $fillable = [
        'name',
        'description',
        'price',
        'active',
        'uuid',
        'metadata',
        'tags',
        'status',
        'image_blob',
        'specifications',
    ];

    /**
     * Validaciones personalizadas.
     */
    protected array $rules = [
        'name'   => ['required', 'min:2', 'max:255'],
        'price'  => ['required', 'numeric', 'min:0'],
        'uuid'   => ['required', 'uuid'],
        'status' => ['required', 'in:draft,published,archived'],
    ];

    /**
     * Define los tipos de propiedades del modelo.
     */
    public static function getPropertyTypes(): array
    {
        return [
            'id' => [
                'type'           => 'int',
                'primary'        => true,
                'auto_increment' => true,
            ],
            'name' => [
                'type'       => 'string',
                'max_length' => 255,
                'required'   => true,
            ],
            'description' => [
                'type'     => 'text',
                'nullable' => true,
            ],
            'price' => [
                'type'      => 'decimal',
                'precision' => 10,
                'scale'     => 2,
                'required'  => true,
            ],
            'active' => [
                'type'    => 'boolean',
                'default' => true,
            ],
            'uuid' => [
                'type'     => 'uuid',
                'unique'   => true,
                'required' => true,
            ],
            'metadata' => [
                'type'     => 'json',
                'nullable' => true,
                'default'  => '{}',
            ],
            'tags' => [
                'type'     => 'set',
                'options'  => ['electronics', 'clothing', 'books', 'home', 'sports'],
                'nullable' => true,
            ],
            'status' => [
                'type'    => 'enum',
                'options' => ['draft', 'published', 'archived'],
                'default' => 'draft',
            ],
            'image_blob' => [
                'type'     => 'blob',
                'nullable' => true,
                'encoding' => 'base64',
            ],
            'specifications' => [
                'type'       => 'array',
                'nullable'   => true,
                'array_type' => 'text[]', // PostgreSQL specific
            ],
            'created_at' => [
                'type'           => 'datetime',
                'auto_timestamp' => true,
            ],
            'updated_at' => [
                'type'           => 'datetime',
                'auto_timestamp' => true,
                'on_update'      => true,
            ],
        ];
    }

    /**
     * Mutadores personalizados.
     */
    public function getMutators(): array
    {
        return [
            'price' => static function ($value) {
                return number_format((float) $value, 2, '.', '');
            },
            'uuid' => static function ($value) {
                return strtolower($value);
            },
            'name' => static function ($value) {
                return ucfirst(trim($value));
            },
        ];
    }

    /**
     * Accesorios personalizados.
     */
    public function getAccessors(): array
    {
        return [
            'formatted_price' => function () {
                return '$' . number_format($this->price, 2);
            },
            'tag_count' => function () {
                return is_array($this->tags) ? count($this->tags) : 0;
            },
            'is_published' => function () {
                return $this->status === 'published';
            },
        ];
    }

    /**
     * Genera un UUID automáticamente si no existe.
     */
    protected function boot(): void
    {
        if (empty($this->uuid)) {
            $this->uuid = $this->generateUuid();
        }
    }

    /**
     * Genera un UUID v4.
     */
    private function generateUuid(): string
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xFFFF),
            mt_rand(0, 0xFFFF),
            mt_rand(0, 0xFFFF),
            mt_rand(0, 0x0FFF) | 0x4000,
            mt_rand(0, 0x3FFF) | 0x8000,
            mt_rand(0, 0xFFFF),
            mt_rand(0, 0xFFFF),
            mt_rand(0, 0xFFFF),
        );
    }
}
