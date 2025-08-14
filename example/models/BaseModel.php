<?php

declare(strict_types=1);

namespace App\Models;

use ReflectionClass;
use VersaORM\QueryBuilder;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

use function is_string;

/**
 * Modelo base para la aplicación.
 */
abstract class BaseModel extends VersaModel
{
    /** Permite asignar cualquier campo salvo que el hijo limite con $guarded específico. */
    protected array $guarded = [];

    /** Cache de nombres de tabla por clase para evitar reflection repetido. */
    private static array $tableNameCache = [];

    // (sin constructor personalizado para compatibilidad con QueryBuilder)

    // ===================== Boot helpers =====================
    public static function boot(array $config): void
    {
        VersaModel::setORM(new VersaORM($config));
    }

    public static function shutdown(): void
    {
        self::orm()->disconnect();
    }

    // ===================== Table helpers =====================
    public static function tableName(): string
    {
        $cls = static::class;

        if (isset(self::$tableNameCache[$cls])) {
            return self::$tableNameCache[$cls];
        }
        // Reflection una sola vez si el hijo define protected string $table
        $refl = new ReflectionClass($cls);

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
        $short = strtolower((new ReflectionClass($cls))->getShortName());

        return self::$tableNameCache[$cls] = $short;
    }

    public function querySelf(): QueryBuilder
    {
        return $this->query();
    }

    // ===================== Métodos instancia (no estáticos) =====================
    /** Obtener todos los registros como modelos tipados (instancia). */
    public function all(): array
    {
        return $this->querySelf()->findAll();
    }

    /** Buscar por ID (instancia). */
    /**
     * Buscar por ID (instancia) devolviendo el modelo tipado concreto.
     */
    public function find(int $id, string $pk = 'id'): ?static
    {
        // @var static|null $m
        return $this->querySelf()->where($pk, '=', $id)->findOne();
    }

    /** Obtener todos como arrays (instancia). */
    public function allArray(): array
    {
        return $this->querySelf()->getAll();
    }

    /** Buscar fila por ID como array (instancia). */
    public function findArray(int $id, string $pk = 'id'): ?array
    {
        $row = $this->querySelf()->where($pk, '=', $id)->firstArray();

        return $row !== null && $row !== [] ? $row : null;
    }

    /** Paginación simple (instancia). */
    public function paginate(int $page = 1, int $perPage = 10): array
    {
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $offset = ($page - 1) * $perPage;
        $items = $this->querySelf()->limit($perPage)->offset($offset)->getAll();
        $total = $this->querySelf()->count();

        return [
            'items' => $items,
            'total' => $total,
            'page' => $page,
            'perPage' => $perPage,
            'totalPages' => (int) ceil($total / $perPage),
        ];
    }

    // ===================== Compatibilidad (find/all) eliminada en modo instancia =====================

    // ===================== Normalización helper (se mantienen) =====================

    /**
     * Método para definir tipos de propiedades (debe ser sobrescrito en modelos hijos).
     */
    public static function definePropertyTypes(): array
    {
        return [];
    }

    // ===================== Query shortcuts =====================
    protected static function qb(?string $table = null): QueryBuilder
    {
        return self::orm()->table($table ?? static::tableName(), static::class);
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
