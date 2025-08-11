<?php

declare(strict_types=1);

namespace App\Models;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Modelo base para la aplicación.
 */
abstract class BaseModel extends VersaModel
{
    /** Permite asignar cualquier campo salvo que el hijo limite con $guarded específico. */
    protected array $guarded = [];

    /** Cache de nombres de tabla por clase para evitar reflection repetido. */
    private static array $tableNameCache = [];

    /* ===================== Boot helpers ===================== */
    public static function boot(array $config): void
    {
        VersaModel::setORM(new VersaORM($config));
    }
    public static function shutdown(): void
    {
        self::orm()->disconnect();
    }

    /* ===================== Table helpers ===================== */
    protected static function tableName(): string
    {
        $cls = static::class;
        if (isset(self::$tableNameCache[$cls])) return self::$tableNameCache[$cls];
        // Reflection una sola vez si el hijo define protected string $table
        $refl = new \ReflectionClass($cls);
        if ($refl->hasProperty('table')) {
            $prop = $refl->getProperty('table');
            $prop->setAccessible(true);
            /** @var mixed $val */
            $val = $prop->isStatic() ? $prop->getValue() : $prop->getValue($refl->newInstanceWithoutConstructor());
            if (is_string($val) && $val !== '') {
                return self::$tableNameCache[$cls] = $val;
            }
        }
        // Fallback al nombre de clase snake plural simple (muy básico)
        $short = strtolower((new \ReflectionClass($cls))->getShortName());
        return self::$tableNameCache[$cls] = $short;
    }

    /* ===================== Query shortcuts ===================== */
    protected static function qb(?string $table = null): QueryBuilder
    {
        return self::orm()->table($table ?? static::tableName(), static::class);
    }
    public function querySelf(): QueryBuilder
    {
        return self::orm()->table(static::tableName(), static::class);
    }

    /* ===================== Compatibilidad (find/all) ===================== */
    /**
     * Compat: encontrar por ID devolviendo el modelo tipado o null.
     */
    public static function find(int $id, string $pk = 'id'): ?static
    {
        /** @var static|null $m */
        $m = static::findOne(static::tableName(), $id, $pk);
        return $m;
    }
    /**
     * Compat: obtener todos los registros como modelos tipados.
     * (Evita tener que definir all() manualmente en cada modelo de ejemplo.)
     * @return array<int, static>
     */
    public static function all(): array
    {
        /** @var array<int, static> $rows */
        $rows = static::findAll(static::tableName());
        return $rows;
    }

    /* ===================== Common operations ===================== */
    public static function allArray(): array
    {
        return static::qb()->getAll();
    }
    public static function allModels(): array
    {
        return static::qb()->findAll();
    }
    public static function findArray(int $id, string $pk = 'id'): ?array
    {
        $row = static::qb()->where($pk, '=', $id)->firstArray();
        return $row ?: null;
    }
    public static function paginate(int $page = 1, int $perPage = 10): array
    {
        $page     = max(1, $page);
        $perPage  = max(1, $perPage);
        $offset   = ($page - 1) * $perPage;
        $qb       = static::qb();
        $items    = $qb->limit($perPage)->offset($offset)->getAll();
        $total    = static::qb()->count();
        return [
            'items'      => $items,
            'total'      => $total,
            'page'       => $page,
            'perPage'    => $perPage,
            'totalPages' => (int)ceil($total / $perPage),
        ];
    }

    /* ===================== Normalización helper (se mantienen) ===================== */

    /**
     * Método para definir tipos de propiedades (debe ser sobrescrito en modelos hijos).
     */
    public static function definePropertyTypes(): array
    {
        return [];
    }

    /**
     * Normalizar campos opcionales que vienen vacíos desde formularios.
     * Convierte cadenas vacías a null para campos que deberían ser null en DB.
     */
    protected function normalizeOptionalFields(array &$attributes, array $optionalFields): void
    {
        foreach ($optionalFields as $field) {
            if (isset($attributes[$field]) && ($attributes[$field] === '' || $attributes[$field] === null)) {
                $attributes[$field] = null;
            }
        }
    }

    /**
     * Normalizar campos de fecha opcionales.
     */
    protected function normalizeOptionalDateFields(array &$attributes, array $dateFields): void
    {
        foreach ($dateFields as $field) {
            if (isset($attributes[$field]) && ($attributes[$field] === '' || $attributes[$field] === null)) {
                $attributes[$field] = null;
            }
        }
    }
}
