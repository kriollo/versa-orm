<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
final class UpsertSaveTest extends TestCase
{
    public function testUpsertThrowsNoData(): void
    {
        $m = new class ('users', null) extends VersaModel {
            protected array $fillable = ['email'];
        };

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires model data');
        $m->upsert(['email']);
    }

    public function testUpsertThrowsNoUniqueKeys(): void
    {
        $m = new class ('users', null) extends VersaModel {
            protected array $fillable = ['email'];
        };
        $m->fill(['email' => 'a@b.com']);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('upsert requires unique keys');
        $m->upsert([]);
    }

    public function testUpsertThrowsWhenNoOrm(): void
    {
        $m = new class ('users', null) extends VersaModel {
            protected array $fillable = ['email'];
        };
        $m->fill(['email' => 'a@b.com']);

        VersaModel::setORM(null);

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('No ORM instance available for upsert operation');
        $m->upsert(['email']);
    }
}
