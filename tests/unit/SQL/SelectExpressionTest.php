<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\SQL;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\SelectExpression;

/**
 * Contrato del parser único de expresiones de proyección.
 *
 * Cubre las dos mitades del problema que motivó el parser:
 *  - SQL legítimo que la validación anterior rechazaba (alias, CAST, aritmética, acentos),
 *  - inyección que no debe pasar, porque las expresiones de función se emiten crudas.
 *
 * @group sqlite
 */
final class SelectExpressionTest extends TestCase
{
    /** @return array<string, array{0: string, 1: string}> */
    public static function legitimateExpressions(): array
    {
        return [
            // caso => [expresión, kind esperado]
            'asterisco' => ['*', 'star'],
            'columna simple' => ['id', 'identifier'],
            'columna calificada' => ['users.id', 'identifier'],
            'tabla.*' => ['users.*', 'identifier'],
            'tres segmentos' => ['db.schema.col', 'identifier'],
            'acentos' => ['año', 'identifier'],
            'acentos con guion bajo' => ['nombre_año', 'identifier'],
            'alias simple' => ['users.name AS author_name', 'identifier'],
            'alias en minuscula' => ['id as ident', 'identifier'],
            'alias con acentos' => ['name AS año', 'identifier'],
            'alias citado con espacio' => ['total AS "Total Ventas"', 'identifier'],
            'alias que empieza con digito' => ['id AS 2024_total', 'identifier'],
            'count estrella' => ['COUNT(*) AS total', 'function'],
            'suma' => ['SUM(amount) AS total_amount', 'function'],
            'count distinct' => ['COUNT(DISTINCT user_id) AS u', 'function'],
            'cast con AS interno' => ['CAST(id AS CHAR) AS idstr', 'function'],
            'funcion anidada' => ['ROUND(AVG(score), 2) AS avg_score', 'function'],
            'aritmetica en argumento' => ['SUM(price * qty) AS total', 'function'],
            'aritmetica entre funciones' => ['MAX(price) - MIN(price) AS spread', 'function'],
            'literal con espacios' => ["CONCAT(first_name, ' ', last_name) AS full_name", 'function'],
            'date_format' => ["DATE_FORMAT(created_at, '%Y') AS y", 'function'],
            'json_extract' => ["JSON_EXTRACT(meta, '$.k') AS k", 'function'],
            'group_concat' => ['GROUP_CONCAT(name) AS g', 'function'],
            'coalesce' => ['COALESCE(nick, name) AS display', 'function'],
            'extract con FROM interno' => ['EXTRACT(YEAR FROM created_at) AS y', 'function'],
            'substring con FROM FOR' => ['SUBSTRING(name FROM 1 FOR 3) AS s', 'function'],
        ];
    }

    /** @return array<string, array{0: string}> */
    public static function maliciousExpressions(): array
    {
        return [
            'fin de sentencia' => ['id; DROP TABLE users'],
            'comentario de linea' => ['id -- x'],
            'comentario de bloque' => ['id /* x */'],
            'comentario con almohadilla' => ['id # x'],
            'subconsulta' => ['(SELECT password FROM admins) AS p'],
            'subconsulta en el alias' => ['COUNT(*) AS a, (SELECT 1) AS b'],
            'union' => ['a UNION SELECT 1'],
            'tautologia' => ['f(1) OR (1=1)'],
            'funcion no permitida' => ['UNKNOWN_FN(x) AS y'],
            'timing con sleep' => ['SLEEP(5) AS s'],
            'timing con benchmark' => ['BENCHMARK(1000000, MD5(1)) AS b'],
            'lectura de archivo' => ["LOAD_FILE('/etc/passwd') AS f"],
            'escape del quoting en el alias' => ['id AS x`, (SELECT 1) AS `y'],
            'escape del quoting en tabla.*' => ['x`,(SELECT 1),`y.*'],
            'literal sin cerrar' => ["CONCAT(a,'unclosed) AS x"],
            'from en nivel superior' => ['COUNT(*) FROM users'],
            'parentesis desbalanceados' => ['COUNT(( AS x'],
            'vacio' => [''],
        ];
    }

    #[DataProvider('legitimateExpressions')]
    public function testAcceptsLegitimateExpression(string $expression, string $expectedKind): void
    {
        $parsed = SelectExpression::parse($expression);

        static::assertNotNull($parsed, sprintf('Se rechazó SQL legítimo: %s', $expression));
        static::assertSame($expectedKind, $parsed['kind'], $expression);
        static::assertTrue(SelectExpression::isValid($expression), $expression);
    }

    #[DataProvider('maliciousExpressions')]
    public function testRejectsMaliciousExpression(string $expression): void
    {
        static::assertNull(
            SelectExpression::parse($expression),
            sprintf('Se aceptó una expresión peligrosa: %s', $expression),
        );
    }

    /**
     * El alias se separa por el ` AS ` de nivel superior, no con preg_split: ésa era la
     * causa de que `CAST(x AS CHAR) AS y` se partiera en dos trozos sin sentido.
     */
    public function testAliasIsSplitAtTopLevelOnly(): void
    {
        $parsed = SelectExpression::parse('CAST(id AS CHAR) AS idstr');

        static::assertNotNull($parsed);
        static::assertSame('CAST(id AS CHAR)', $parsed['expr']);
        static::assertSame('idstr', $parsed['alias']);
    }

    public function testQualifiedIdentifierKeepsItsSegments(): void
    {
        $parsed = SelectExpression::parse('users.name AS author');

        static::assertNotNull($parsed);
        static::assertSame(['users', 'name'], $parsed['parts']);
        static::assertSame('author', $parsed['alias']);
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function tableReferences(): array
    {
        return [
            'tabla' => ['users', 'users'],
            'con esquema' => ['public.users', 'public.users'],
            'alias con AS' => ['users AS u', 'users'],
            'alias implicito' => ['users u', 'users'],
        ];
    }

    #[DataProvider('tableReferences')]
    public function testParsesTableReference(string $input, string $expectedTable): void
    {
        $parsed = SelectExpression::parseTableReference($input);

        static::assertNotNull($parsed, $input);
        static::assertSame($expectedTable, $parsed['table']);
    }

    public function testRejectsStarAsTableReference(): void
    {
        static::assertNull(SelectExpression::parseTableReference('users.*'));
    }

    /**
     * Los identificadores son seguros porque el compilador los cita, no porque un regex
     * los apruebe: palabras reservadas y acentos tienen que sobrevivir el viaje completo.
     */
    public function testReservedWordsAndAccentsSurviveCompilation(): void
    {
        $dialect = new MySQLDialect();

        static::assertSame('`order`', $dialect->quoteIdentifier('order'));
        static::assertSame('`año`', $dialect->quoteIdentifier('año'));
        static::assertTrue(SelectExpression::isValid('order'));
        static::assertTrue(SelectExpression::isValid('año'));
    }
}
