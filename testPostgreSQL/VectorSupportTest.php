<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaORMException;

/**
 * Suite de tests de soporte RAG nativo con pgvector.
 *
 * Requiere PostgreSQL con la extensión pgvector instalada.
 * Si pgvector no está disponible el test completo se saltea automáticamente.
 *
 * @group postgresql
 * @group pgvector
 */
class VectorSupportTest extends TestCase
{
    /** Nombre de la tabla usada en estos tests, aislada del resto de la suite. */
    private const TABLE = 'rag_test_docs';

    // -------------------------------------------------------------------------
    // Ciclo de vida: setUp / tearDown solo operan sobre la tabla vectorial
    // Se sobreescribe setUp/tearDown para no ejecutar el schema general.
    // -------------------------------------------------------------------------

    protected function setUp(): void
    {
        // No llamamos a parent::setUp() para no crear el schema base —
        // este test administra su propia tabla.
        $schema = self::$orm->schemaBuilder();

        try {
            $schema->enablePgVector();
        } catch (\Exception $e) {
            $this->markTestSkipped('pgvector no está disponible en este servidor PostgreSQL: ' . $e->getMessage());
        }

        // Limpiar si existe de una ejecución anterior
        self::$orm->exec('DROP TABLE IF EXISTS ' . self::TABLE);

        $schema->create(self::TABLE, static function ($table): void {
            $table->id();
            $table->string('title', 255);
            $table->vector('embedding', 3); // 3 dims para tests simples
            $table->tsvector('search_vector')->nullable();
            $table->timestamps();
        });
    }

    protected function tearDown(): void
    {
        self::$orm->exec('DROP TABLE IF EXISTS ' . self::TABLE);
    }

    // =========================================================================
    // Grupo A — Schema: creación de tablas, columnas e índices
    // =========================================================================

    /** @test */
    public function test_can_enable_pgvector(): void
    {
        // Si llegamos aquí, enablePgVector() ya fue llamado en setUp() sin lanzar excepción.
        static::assertTrue(true);
    }

    /** @test */
    public function test_can_create_table_with_vector_column(): void
    {
        $result = self::$orm->getAll("SELECT column_name, data_type, udt_name
             FROM information_schema.columns
             WHERE table_name = ?
               AND column_name = 'embedding'", [self::TABLE]);

        static::assertNotEmpty($result, 'La columna embedding debe existir en information_schema');

        $row = $result[0];
        // pgvector se registra como tipo USER-DEFINED cuyo udt_name es 'vector'
        static::assertSame('vector', strtolower((string) ($row['udt_name'] ?? '')));
    }

    /** @test */
    public function test_can_create_table_with_tsvector_column(): void
    {
        $result = self::$orm->getAll("SELECT column_name, data_type
             FROM information_schema.columns
             WHERE table_name = ?
               AND column_name = 'search_vector'", [self::TABLE]);

        static::assertNotEmpty($result, 'La columna search_vector debe existir');
        static::assertSame('tsvector', strtolower((string) ($result[0]['data_type'] ?? '')));
    }

    /** @test */
    public function test_vector_column_accepts_embeddings(): void
    {
        self::$orm->exec(
            'INSERT INTO ' . self::TABLE . ' (title, embedding, created_at, updated_at)
             VALUES (?, ?::vector, NOW(), NOW())',
            ['Doc A', '[1,0,0]'],
        );

        $row = self::$orm->getRow('SELECT title FROM ' . self::TABLE . " WHERE title = 'Doc A'");
        static::assertNotNull($row);
        static::assertSame('Doc A', $row['title']);
    }

    /** @test */
    public function test_can_create_hnsw_index(): void
    {
        $schema = self::$orm->schemaBuilder();

        // No debe lanzar excepción
        $schema->table(self::TABLE, static function ($table): void {
            $table->vectorIndex('embedding', 'hnsw', 'vector_cosine_ops', ['m' => 16, 'ef_construction' => 64]);
        });

        static::assertTrue(true);
    }

    /** @test */
    public function test_can_create_ivfflat_index(): void
    {
        $schema = self::$orm->schemaBuilder();

        $schema->table(self::TABLE, static function ($table): void {
            $table->vectorIndex('embedding', 'ivfflat', 'vector_cosine_ops', ['lists' => 100]);
        });

        static::assertTrue(true);
    }

    /** @test */
    public function test_invalid_index_method_throws(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessageMatches('/método.*no soportado/i');

        $schema = self::$orm->schemaBuilder();
        $schema->table(self::TABLE, static function ($table): void {
            $table->vectorIndex('embedding', 'invalid_method', 'vector_cosine_ops');
        });
    }

    /** @test */
    public function test_invalid_index_metric_throws(): void
    {
        $this->expectException(VersaORMException::class);
        $this->expectExceptionMessageMatches('/métrica.*no soportada/i');

        $schema = self::$orm->schemaBuilder();
        $schema->table(self::TABLE, static function ($table): void {
            $table->vectorIndex('embedding', 'hnsw', 'invalid_metric_ops');
        });
    }

    // =========================================================================
    // Grupo B — QueryBuilder: similitud coseno
    // =========================================================================

    /** @test */
    public function test_cosine_similarity_returns_correct_order(): void
    {
        $this->insertTestDocuments();

        // [1,0,0] debería ser el más cercano a [0.9,0.1,0]
        $query = [0.9, 0.1, 0.0];
        $result = self::$orm
            ->table(self::TABLE)
            ->selectVectorSimilarity('embedding', $query, 'cosine', 'similarity')
            ->select(['title'])
            ->orderBySimilarity('embedding', $query, 'cosine', 'asc')
            ->limit(3)
            ->get();

        static::assertNotEmpty($result);
        // El primer resultado debe ser el doc cuyo embedding es [1,0,0]
        static::assertSame('Doc A', $result[0]['title']);
    }

    /** @test */
    public function test_cosine_similarity_with_threshold(): void
    {
        $this->insertTestDocuments();

        // Umbral alto: solo documentos muy similares a [1,0,0]
        $query = [1.0, 0.0, 0.0];
        $result = self::$orm
            ->table(self::TABLE)
            ->whereVectorSimilarity('embedding', $query, 0.99, 'cosine')
            ->select(['title'])
            ->get();

        // Solo Doc A ([1,0,0]) debe superar el umbral 0.99 de similitud coseno con [1,0,0]
        static::assertCount(1, $result);
        static::assertSame('Doc A', $result[0]['title']);
    }

    // =========================================================================
    // Grupo C — QueryBuilder: similitud L2
    // =========================================================================

    /** @test */
    public function test_l2_distance_returns_correct_order(): void
    {
        $this->insertTestDocuments();

        // [1,0,0] tiene distancia L2 = 0 respecto a sí mismo
        $query = [1.0, 0.0, 0.0];
        $result = self::$orm
            ->table(self::TABLE)
            ->orderBySimilarity('embedding', $query, 'l2', 'asc')
            ->select(['title'])
            ->limit(3)
            ->get();

        static::assertNotEmpty($result);
        static::assertSame('Doc A', $result[0]['title']);
    }

    /** @test */
    public function test_l2_distance_with_threshold(): void
    {
        $this->insertTestDocuments();

        // L2: 1 - distancia >= threshold → distancia <= 1 - threshold
        // Para [0,0,1] vs [1,0,0]: distancia L2 = sqrt(2) ≈ 1.41 → similitud = 1 - 1.41 < 0
        // Para [1,0,0] vs [1,0,0]: distancia L2 = 0 → similitud = 1.0
        $query = [1.0, 0.0, 0.0];
        $result = self::$orm
            ->table(self::TABLE)
            ->whereVectorSimilarity('embedding', $query, 0.8, 'l2')
            ->select(['title'])
            ->get();

        // Solo Doc A tiene distancia L2 = 0 (similitud = 1.0 >= 0.8)
        static::assertCount(1, $result);
        static::assertSame('Doc A', $result[0]['title']);
    }

    // =========================================================================
    // Grupo D — QueryBuilder: similitud inner product
    // =========================================================================

    /** @test */
    public function test_inner_product_returns_correct_order(): void
    {
        $this->insertTestDocuments();

        // Con inner_product, mayor producto escalar = más similar
        // [1,0,0] · [0.9,0.1,0] = 0.9 (máximo entre los 3 docs)
        $query = [0.9, 0.1, 0.0];
        $result = self::$orm
            ->table(self::TABLE)
            ->orderBySimilarity('embedding', $query, 'inner_product', 'asc')
            ->select(['title'])
            ->limit(3)
            ->get();

        static::assertNotEmpty($result);
        // Doc A debería estar primero (mayor producto escalar con la query)
        static::assertSame('Doc A', $result[0]['title']);
    }

    // =========================================================================
    // Helpers privados
    // =========================================================================

    /**
     * Inserta 3 documentos con embeddings ortogonales para tests de similitud.
     *
     * Doc A: [1, 0, 0] — eje X
     * Doc B: [0, 1, 0] — eje Y
     * Doc C: [0, 0, 1] — eje Z
     */
    private function insertTestDocuments(): void
    {
        $docs = [
            ['Doc A', '[1,0,0]'],
            ['Doc B', '[0,1,0]'],
            ['Doc C', '[0,0,1]'],
        ];

        foreach ($docs as [$title, $vector]) {
            self::$orm->exec(
                'INSERT INTO ' . self::TABLE . ' (title, embedding, created_at, updated_at)
                 VALUES (?, ?::vector, NOW(), NOW())',
                [$title, $vector],
            );
        }
    }
}
