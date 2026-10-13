<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

class VersaORMStub3 extends VersaORM
{
    public function __construct() {}

    public function executeQuery(string $action, array $params = [])
    {
        return [];
    }
}

/**
 * @group sqlite
 */
final class QueryBuilderSecurityTest extends TestCase
{
    private QueryBuilder $qb;

    protected function setUp(): void
    {
        $orm = new VersaORMStub3();
        $this->qb = new QueryBuilder($orm, 'users');
    }

    /**
     * select() acepta lo que es representable de forma segura y lo emite compilado.
     * Se prueba por la API pública y no por reflexión; el contrato detallado del parser
     * está en tests/unit/SQL/SelectExpressionTest.php.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function acceptedColumns(): array
    {
        return [
            // columna => [entrada, fragmento que debe aparecer en el SQL compilado]
            'asterisco' => ['*', 'SELECT *'],
            'tabla' => ['users', '`users`'],
            'alias en minuscula' => ['users.name as author', '`users`.`name` AS `author`'],
            'count' => ['COUNT(*) AS total', 'COUNT(*) AS `total`'],
            'max' => ['MAX(price) AS mx', 'MAX(price) AS `mx`'],
            // Las cuatro siguientes las rechazaba el validador anterior aunque son SQL válido.
            'cast con AS interno' => ['CAST(id AS CHAR) AS idstr', 'CAST(id AS CHAR) AS `idstr`'],
            'funcion anidada' => ['ROUND(AVG(score), 2) AS avg_score', 'ROUND(AVG(score), 2) AS `avg_score`'],
            'acentos' => ['año', '`año`'],
            // Un identificador que empieza por dígito es legal si va citado, y se cita.
            'empieza por digito' => ['1weird', '`1weird`'],
        ];
    }

    #[DataProvider('acceptedColumns')]
    public function testSelectAcceptsLegitimateColumn(string $column, string $expectedFragment): void
    {
        $sql = $this->qb->select([$column])->toSql();

        static::assertStringContainsString($expectedFragment, $sql, sprintf('columna: %s', $column));
    }

    public function testSelectRejectsMaliciousColumns(): void
    {
        foreach ([
            'users; DROP TABLE users',
            'id -- x',
            '(SELECT password FROM admins) AS p',
            'BADFUNC(1) AS x',
            'SLEEP(10) AS s',
        ] as $column) {
            try {
                $this->qb->select([$column]);
                static::fail(sprintf('select() aceptó una columna peligrosa: %s', $column));
            } catch (VersaORMException $e) {
                static::assertStringContainsString('Invalid or malicious', $e->getMessage());
            }
        }
    }

    public function testIsSafeRawExpressionRejectsDangerousPatterns(): void
    {
        $ref = new \ReflectionClass($this->qb);
        $m = $ref->getMethod('isSafeRawExpression');
        $m->setAccessible(true);

        static::assertTrue($m->invoke($this->qb, 'SELECT id FROM users'));
        static::assertFalse($m->invoke($this->qb, 'SELECT * FROM users; DROP TABLE secret;'));
        static::assertFalse($m->invoke($this->qb, str_repeat('(', 600)));
    }
}
