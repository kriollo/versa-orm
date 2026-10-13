<?php

declare(strict_types=1);

namespace VersaORM\Relations;

use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

class BelongsToMany extends Relation
{
    public function __construct(
        QueryBuilder $query,
        VersaModel $parent,
        public string $pivotTable,
        public string $foreignPivotKey,
        public string $relatedPivotKey,
        public string $parentKey,
        public string $relatedKey,
    ) {
        parent::__construct($query, $parent);
    }

    /**
     * Redirigir llamadas al QueryBuilder interno.
     *
     * @param string $method
     * @param array<mixed> $arguments
     *
     * @return mixed
     *
     * @phpstan-ignore-next-line
     */
    public function __call($method, $arguments)
    {
        $this->applyConstraintsOnce();

        /** @phpstan-ignore-next-line */
        return $this->query->$method(...$arguments);
    }

    public function query(): QueryBuilder
    {
        $this->applyConstraintsOnce();

        return $this->query;
    }

    /**
     * @return array<int, VersaModel>
     */
    public function getResults(): array
    {
        $this->applyConstraintsOnce();

        return $this->query->findAll();
    }

    /**
     * Adjunta un registro relacionado a la tabla pivote.
     *
     * @param int|string $id El ID del registro relacionado a adjuntar
     * @param array<string, mixed> $attributes Atributos adicionales para la tabla pivote
     *
     * @throws \Exception Si ocurre un error durante la inserción
     */
    public function attach($id, array $attributes = []): void
    {
        $pivotQuery = $this->query->from($this->pivotTable);

        $data = array_merge([
            $this->foreignPivotKey => $this->parent->getAttribute($this->parent->getKeyName()),
            $this->relatedPivotKey => $id,
        ], $attributes);

        $reflection = new \ReflectionClass($pivotQuery);
        $executeMethod = $reflection->getMethod('execute');
        $executeMethod->setAccessible(true);
        $executeMethod->invoke($pivotQuery, 'insert', $data);
    }

    /**
     * Sincroniza los registros relacionados en la tabla pivote.
     *
     * @param array<int, int|string> $ids Array de IDs a sincronizar
     *
     * @throws \Exception Si ocurre un error durante la sincronización
     *
     * @return array{attached: array<int, int|string>, detached: array<int, int|string>}
     */
    public function sync(array $ids): array
    {
        $parentKey = $this->parent->getAttribute($this->parent->getKeyName());

        $currentQuery = $this->query->from($this->pivotTable)->where($this->foreignPivotKey, '=', $parentKey);

        $current = $currentQuery->get();

        // array_diff compara como strings, así que se indexa por la forma en string
        // pero se conservan los valores ORIGINALES: así `sync()` sigue devolviendo los
        // ids con el tipo que recibió (int o string) y no se altera su contrato.
        $index = static function (array $values): array {
            $map = [];

            foreach ($values as $value) {
                if (is_int($value) || is_string($value)) {
                    $map[(string) $value] = $value;
                }
            }

            return $map;
        };
        $currentById = $index(array_column($current, $this->relatedPivotKey));
        $wantedById = $index($ids);

        /** @var array<int, int|string> $detached */
        $detached = array_values(array_diff_key($currentById, $wantedById));
        /** @var array<int, int|string> $attached */
        $attached = array_values(array_diff_key($wantedById, $currentById));

        if (count($detached) > 0) {
            $this->detach($detached);
        }

        foreach ($attached as $id) {
            $this->attach($id);
        }

        return ['attached' => $attached, 'detached' => $detached];
    }

    /**
     * Separa registros relacionados de la tabla pivote.
     *
     * @param array<int, int|string>|int|string|null $ids IDs específicos a separar
     *
     * @throws \Exception Si ocurre un error durante la eliminación
     *
     * @return void
     */
    public function detach($ids = null): void
    {
        $parentKey = $this->parent->getAttribute($this->parent->getKeyName());

        $deleteQuery = $this->query->from($this->pivotTable)->where($this->foreignPivotKey, '=', $parentKey);

        if ($ids !== null) {
            $ids = is_array($ids) ? $ids : [$ids];
            $deleteQuery->whereIn($this->relatedPivotKey, $ids);
        }

        $deleteQuery->delete();
    }

    protected function addConstraints(): void
    {
        $this->query->join(
            $this->pivotTable,
            $this->query->getTable() . '.' . $this->relatedKey,
            '=',
            $this->pivotTable . '.' . $this->relatedPivotKey,
        );
        $this->query->where(
            $this->pivotTable . '.' . $this->foreignPivotKey,
            '=',
            $this->parent->getAttribute($this->parentKey),
        );
    }
}
