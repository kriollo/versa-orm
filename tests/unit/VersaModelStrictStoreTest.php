<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 * @group core
 */
class VersaModelStrictStoreTest extends TestCase
{
    public function testStoreThrowsExceptionWithoutId()
    {
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        // Mock VersaORM to simulate insert failure or returning null
        $ormMock = $this->createMock(VersaORM::class);
        $ormMock->method('isDebugMode')->willReturn(true);
        // We can't easily mock the chained methods without complex mocking.
        // Instead, let's test strict behavior using a real instance but force failure?
        // Or better, verify that VersaModel::store throws logic.

        // Strategy: Use a partial mock of VersaModel to override logic? No, we want to test store() logic.
        // Strategy: Mock the ORM instance injected into VersaModel.

        // We need to mock: $orm->table(...)->insertGetId(...) -> returns null

        $queryBuilderMock = $this
            ->getMockBuilder(\VersaORM\QueryBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();

        // Strict verification: Ensure we actually attempt the insert
        $queryBuilderMock->expects($this->once())->method('insertGetId')->willReturn(null);

        $ormMock->method('table')->willReturn($queryBuilderMock);
        // By default mocks return null, which might cause ensureColumnsExist to fail silently or throw.
        // Let's ensure isFrozen returns true so we skip schema checks for this test, isolating the store() logic.
        $ormMock->method('isFrozen')->willReturn(true);

        $model = new class('users', $ormMock) extends VersaModel {
            protected array $fillable = ['name'];
        };

        $model->name = 'Test User';

        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessage('Could not determine ID');

        $model->store();
    }
}
