<?php

declare(strict_types=1);

namespace VersaORM\Interfaces;

/**
 * Interface para modelos con tipado fuerte.
 * Define la estructura que deben implementar los modelos para soporte completo de tipos.
 */
interface TypedModelInterface
{
    /**
     * Define los tipos de propiedades del modelo.
     *
     * @return array<string, array<string, mixed>> Mapeo de campos a sus definiciones de tipo
     */
    public static function getPropertyTypes(): array;

    /**
     * Valida que el esquema del modelo sea consistente con la base de datos.
     *
     * @return array<string> Array de errores de consistencia (vacío si es consistente)
     */
    public function validateSchemaConsistency(): array;

    /**
     * Convierte un valor crudo de la base de datos al tipo PHP apropiado.
     *
     * @param  string $property
     * @param  mixed  $value
     * @return mixed
     */
    public function castToPhpType(string $property, $value);

    /**
     * Convierte un valor PHP al formato apropiado para la base de datos.
     *
     * @param  string $property
     * @param  mixed  $value
     * @return mixed
     */
    public function castToDatabaseType(string $property, $value);

    /**
     * Obtiene los mutadores definidos para las propiedades del modelo.
     *
     * @return array<string, callable>
     */
    public function getMutators(): array;

    /**
     * Obtiene los accesorios definidos para las propiedades del modelo.
     *
     * @return array<string, callable>
     */
    public function getAccessors(): array;
}
