<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

trait HasRelationships
{
    protected array $relations = [];

    public function hasOne(string $related, string $foreignKey = null, string $localKey = null): HasOne
    {
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        /** @var VersaModel $instance */
        $instance = new $related();

        return new HasOne($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    public function hasMany(string $related, string $foreignKey = null, string $localKey = null): HasMany
    {
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        /** @var VersaModel $instance */
        $instance = new $related();

        return new HasMany($instance->newQuery(), $this, $foreignKey, $localKey);
    }

    public function belongsTo(string $related, string $foreignKey = null, string $ownerKey = null, string $relation = null): BelongsTo
    {
        $relation = $relation ?: $this->getRelationName();
        $foreignKey = $foreignKey ?: $relation . '_id';
        $ownerKey = $ownerKey ?: (new $related())->getKeyName();

        /** @var VersaModel $instance */
        $instance = new $related();

        return new BelongsTo($instance->newQuery(), $this, $foreignKey, $ownerKey, $relation);
    }

    public function getRelationValue(string $key)
    {
        if ($this->relationLoaded($key)) {
            return $this->relations[$key];
        }

        if (method_exists($this, $key)) {
            return $this->getRelationshipFromMethod($key);
        }
    }

    public function relationLoaded(string $key): bool
    {
        return array_key_exists($key, $this->relations);
    }

    protected function getRelationshipFromMethod(string $method)
    {
        $relation = $this->$method();

        if (!$relation instanceof Relation) {
            throw new \Exception('Relationship method must return an object of type Relation.');
        }

        return $this->relations[$method] = $relation->getResults();
    }

    public function setRelation(string $relation, $value): void
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