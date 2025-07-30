<?php

declare(strict_types=1);

namespace VersaORM\Traits;

use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\BelongsToMany;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\VersaModel;

trait HasRelationships
{
    /**
     * Define a one-to-one relationship.
     *
     * @param  class-string<VersaModel>  $relatedModel
     * @param  string|null  $foreignKey
     * @param  string|null  $localKey
     * @return HasOne
     */
    public function hasOne(string $relatedModel, ?string $foreignKey = null, ?string $localKey = null): HasOne
    {
        /** @var VersaModel $this */
        $instance = new $relatedModel();
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        return new HasOne($instance->newQuery(), $this, $instance->getTable() . '.' . $foreignKey, $localKey);
    }

    /**
     * Define an inverse one-to-one or many-to-one relationship.
     *
     * @param  class-string<VersaModel>  $relatedModel
     * @param  string|null  $foreignKey
     * @param  string|null  $ownerKey
     * @return BelongsTo
     */
    public function belongsTo(string $relatedModel, ?string $foreignKey = null, ?string $ownerKey = null): BelongsTo
    {
        /** @var VersaModel $this */
        $instance = new $relatedModel();
        $relationName = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'];
        $foreignKey = $foreignKey ?: $relationName . '_id';
        $ownerKey = $ownerKey ?: $instance->getKeyName();

        return new BelongsTo($instance->newQuery(), $this, $foreignKey, $ownerKey, $relationName);
    }

    /**
     * Define a one-to-many relationship.
     *
     * @param  class-string<VersaModel>  $relatedModel
     * @param  string|null  $foreignKey
     * @param  string|null  $localKey
     * @return HasMany
     */
    public function hasMany(string $relatedModel, ?string $foreignKey = null, ?string $localKey = null): HasMany
    {
        /** @var VersaModel $this */
        $instance = new $relatedModel();
        $foreignKey = $foreignKey ?: $this->getForeignKey();
        $localKey = $localKey ?: $this->getKeyName();

        return new HasMany($instance->newQuery(), $this, $instance->getTable() . '.' . $foreignKey, $localKey);
    }

    /**
     * Define a many-to-many relationship.
     *
     * @param  class-string<VersaModel>  $relatedModel
     * @param  string|null  $pivotTable
     * @param  string|null  $foreignPivotKey
     * @param  string|null  $relatedPivotKey
     * @param  string|null  $parentKey
     * @param  string|null  $relatedKey
     * @return BelongsToMany
     */
    public function belongsToMany(
        string $relatedModel,
        ?string $pivotTable = null,
        ?string $foreignPivotKey = null,
        ?string $relatedPivotKey = null,
        ?string $parentKey = null,
        ?string $relatedKey = null
    ): BelongsToMany {
        /** @var VersaModel $this */
        $instance = new $relatedModel();

        // Default pivot table name (e.g., 'post_user')
        $pivotTable = $pivotTable ?: strtolower(
            implode('_', sorted_array([$this->getTable(), $instance->getTable()]))
        );

        $foreignPivotKey = $foreignPivotKey ?: $this->getForeignKey();
        $relatedPivotKey = $relatedPivotKey ?: $instance->getForeignKey();
        $parentKey = $parentKey ?: $this->getKeyName();
        $relatedKey = $relatedKey ?: $instance->getKeyName();

        return new BelongsToMany(
            $instance->newQuery(),
            $this,
            $pivotTable,
            $foreignPivotKey,
            $relatedPivotKey,
            $parentKey,
            $relatedKey
        );
    }
}
