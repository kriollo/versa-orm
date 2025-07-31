<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\Relations\Relation;
use VersaORM\VersaModel;

trait HasRelationships
{
    /** @var array<string, mixed> */
    protected array $relations = [];

    /**
     * @param class-string<VersaModel> $related
     * @param string|null $foreignKey
     * @param string|null $localKey
     * @return HasOne
     */
    public function hasOne(string $related, string $foreignKey = null, string $localKey = null): HasOne
    {
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection = new \ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        $table = $defaultProperties['table'] ?? 'dummy'; // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->orm);

        return new HasOne($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    /**
     * @param class-string<VersaModel> $related
     * @param string|null $foreignKey
     * @param string|null $localKey
     * @return HasMany
     */
    public function hasMany(string $related, string $foreignKey = null, string $localKey = null): HasMany
    {
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection = new \ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        $table = $defaultProperties['table'] ?? 'dummy'; // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->orm);

        return new HasMany($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    /**
     * @param class-string<VersaModel> $related
     * @param string|null $foreignKey
     * @param string|null $ownerKey
     * @param string|null $relation
     * @return BelongsTo
     */
    public function belongsTo(string $related, string $foreignKey = null, string $ownerKey = null, string $relation = null): BelongsTo
    {
        $relation = $relation ?: $this->getRelationName();
        $foreignKey = $foreignKey ?: $relation . '_id';
        
        // Obtener el nombre de la tabla del modelo relacionado usando reflexión
        $reflection = new \ReflectionClass($related);
        $defaultProperties = $reflection->getDefaultProperties();
        $table = $defaultProperties['table'] ?? 'dummy'; // Usar un nombre de tabla predeterminado si no se encuentra

        $instance = new $related($table, $this->orm);
        $ownerKey = $ownerKey ?: $instance->getKeyName();

        return new BelongsTo($instance->newQuery(), $this, $foreignKey, $ownerKey, $relation);
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

    protected function getRelationshipFromMethod(string $method): mixed
    {
        $relation = $this->$method();

        if (!$relation instanceof Relation) {
            throw new \Exception('Relationship method must return an object of type Relation.');
        }

        return $this->relations[$method] = $relation->getResults();
    }

    public function setRelation(string $relation, mixed $value): void
    {
        $this->relations[$relation] = $value;
    }

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
}