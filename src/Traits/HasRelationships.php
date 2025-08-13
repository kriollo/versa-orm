<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use Exception;
use ReflectionClass;
use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\BelongsToMany;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\Relations\Relation;
use VersaORM\VersaModel;

use function array_key_exists;

trait HasRelationships
{
    /**
     * @var array<string, mixed>
     */
    protected array $relations = [];

    public function __get($key)
    {
        if ($this->relationLoaded($key)) {
            return $this->relations[$key];
        }

        if (method_exists($this, $key)) {
            return $this->getRelationshipFromMethod($key);
        }

        return $this->getAttribute($key);
    }

    /**
     * @param class-string<VersaModel> $related
     */
    public function hasOne(string $related, ?string $foreignKey = null, ?string $localKey = null): HasOne
    {
        $foreignKey = $foreignKey !== null ? $foreignKey : $this->getForeignKey();
        $localKey   = $localKey !== null ? $localKey : $this->getKeyName();

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection        = new ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        /** @var string $table */
        $table = (string) ($defaultProperties['table'] ?? 'dummy'); // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->getOrm());

        return new HasOne($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    /**
     * @param class-string<VersaModel> $related
     */
    public function hasMany(string $related, ?string $foreignKey = null, ?string $localKey = null): HasMany
    {
        $foreignKey = $foreignKey !== null ? $foreignKey : $this->getForeignKey();
        $localKey   = $localKey !== null ? $localKey : $this->getKeyName();

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection        = new ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        /** @var string $table */
        $table = (string) ($defaultProperties['table'] ?? 'dummy'); // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->getOrm());

        return new HasMany($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    /**
     * @param class-string<VersaModel> $related
     */
    public function belongsTo(string $related, ?string $foreignKey = null, ?string $ownerKey = null, ?string $relation = null): BelongsTo
    {
        $relation   = $relation !== null ? $relation : $this->getRelationName();
        $foreignKey = $foreignKey !== null ? $foreignKey : $relation . '_id';

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection        = new ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        /** @var string $table */
        $table = (string) ($defaultProperties['table'] ?? 'dummy'); // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->getOrm());
        $ownerKey = $ownerKey !== null ? $ownerKey : $instance->getKeyName();

        return new BelongsTo($instance->newQuery(), $this, $foreignKey, $ownerKey, $relation);
    }

    /**
     * @param class-string<VersaModel> $related
     */
    public function belongsToMany(string $related, string $pivotTable, ?string $foreignPivotKey = null, ?string $relatedPivotKey = null, ?string $parentKey = null, ?string $relatedKey = null): BelongsToMany
    {
        $foreignPivotKey = $foreignPivotKey !== null ? $foreignPivotKey : $this->getForeignKey();
        $relatedPivotKey = $relatedPivotKey !== null ? $relatedPivotKey : (new $related('dummy', $this->getOrm()))->getForeignKey();
        $parentKey       = $parentKey !== null ? $parentKey : $this->getKeyName();

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection        = new ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        /** @var string $table */
        $table = (string) ($defaultProperties['table'] ?? 'dummy'); // Usar un nombre de tabla predeterminado si no se encuentra

        $instance   = new $related($table, $this->getOrm());
        $relatedKey = $relatedKey !== null ? $relatedKey : $instance->getKeyName();

        return new BelongsToMany($instance->newQuery(), $this, $pivotTable, $foreignPivotKey, $relatedPivotKey, $parentKey, $relatedKey);
    }

    /**
     * @return array<string, mixed>
     */
    public function getRelations(): array
    {
        return $this->relations;
    }

    public function getRelationValue(string $key): mixed
    {
        if ($this->relationLoaded($key)) {
            return $this->relations[$key];
        }

        if (method_exists($this, $key)) {
            return $this->getRelationshipFromMethod($key);
        }

        return null;
    }

    public function relationLoaded(string $key): bool
    {
        return array_key_exists($key, $this->relations);
    }

    public function setRelation(string $relation, mixed $value): void
    {
        $this->relations[$relation] = $value;
    }

    protected function getRelationshipFromMethod(string $method): mixed
    {
        $relation = $this->{$method}();

        if (!$relation instanceof Relation) {
            throw new Exception('Relationship method must return an object of type Relation.');
        }

        $result                   = $relation->getResults();
        $this->relations[$method] = $result;

        return $result;
    }
}
