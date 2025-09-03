<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\HasMany;
use VersaORM\VersaModel;

class UserQBTestModel extends VersaModel
{
    protected string $table = 'users';

    public function posts(): HasMany
    {
        return $this->hasMany(PostQBTestModel::class, 'user_id');
    }
}

class PostQBTestModel extends VersaModel
{
    protected string $table = 'posts';

    public function user(): BelongsTo
    {
        return $this->belongsTo(UserQBTestModel::class, 'user_id');
    }
}

class RelationshipsQueryBuilderTest extends TestCase
{
    public function test_count_posts_via_relation_query_builder(): void
    {
        $user = UserQBTestModel::findOne('users', 1);
        $count = $user->posts()->where('id', '>', 0)->count();
        static::assertIsInt($count);
        static::assertGreaterThanOrEqual(0, $count);
    }

    public function test_first_post_via_relation_query_builder(): void
    {
        $user = UserQBTestModel::findOne('users', 1);
        $post = $user->posts()->orderBy('id', 'asc')->firstArray();
        static::assertIsArray($post);
        static::assertArrayHasKey('id', $post);
    }

    public function test_dual_access_consistency(): void
    {
        $user = UserQBTestModel::findOne('users', 1);
        $postsViaProperty = $user->posts;
        $postsViaMethod = $user->posts()->findAll();
        static::assertSame(count($postsViaProperty), count($postsViaMethod));
    }
}
