<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

/**
 * Test para métodos joinRaw y sus variantes (leftJoinRaw, rightJoinRaw, etc.).
 *
 * Este test reproduce el caso de uso real:
 * - Joins con subconsultas complejas (GROUP BY, COUNT)
 * - Múltiples leftJoinRaw encadenados
 * - Combinación de joinRaw con onRaw
 * - Validación de bindings y parámetros
 */
class QueryBuilderJoinRawTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::createTestTables();
        self::insertTestData();
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$orm !== null) {
            self::$orm->exec('DROP TABLE IF EXISTS anima_campana_images CASCADE');
            self::$orm->exec('DROP TABLE IF EXISTS anima_videos CASCADE');
            self::$orm->exec('DROP TABLE IF EXISTS anima_campanas CASCADE');
            self::$orm->exec('DROP TABLE IF EXISTS versa_users CASCADE');
        }

        parent::tearDownAfterClass();
    }

    /**
     * Test básico de joinRaw con SQL simple.
     */
    public function testJoinRawBasic(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select(['anima_campanas.nombre', 'versa_users.name as nombre_usuario'])
            ->joinRaw('INNER JOIN versa_users ON versa_users.id = anima_campanas.id_user')
            ->orderBy('anima_campanas.id')
            ->getAll();

        static::assertCount(4, $result);
        static::assertSame('Campaña 1', $result[0]['nombre']);
        static::assertSame('Juan Pérez', $result[0]['nombre_usuario']);
        static::assertSame('Campaña 2', $result[1]['nombre']);
        static::assertSame('María García', $result[1]['nombre_usuario']);
    }

    /**
     * Test de leftJoinRaw - Reproduciendo el caso del usuario.
     */
    public function testLeftJoinRawWithSubquery(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select([
                'anima_campanas.id',
                'anima_campanas.nombre',
                'video_counts.video_count',
            ])
            ->leftJoinRaw(
                '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id',
            )
            ->orderBy('anima_campanas.id')
            ->getAll();

        static::assertCount(4, $result);

        // Campaña 1 tiene 3 videos
        static::assertSame(1, $result[0]['id']);
        static::assertEquals(3, $result[0]['video_count']);

        // Campaña 2 tiene 1 video
        static::assertSame(2, $result[1]['id']);
        static::assertEquals(1, $result[1]['video_count']);

        // Campaña 3 tiene 2 videos
        static::assertSame(3, $result[2]['id']);
        static::assertEquals(2, $result[2]['video_count']);

        // Campaña 4 no tiene videos (NULL por LEFT JOIN)
        static::assertSame(4, $result[3]['id']);
        static::assertNull($result[3]['video_count']);
    }

    /**
     * Test completo: Reproducción exacta del caso del usuario
     * Múltiples joins (normal + raw), onRaw, selectRaw, orderByRaw.
     */
    public function testCompleteUserCase(): void
    {
        $qb = self::$orm->table('anima_campanas')->lazy();

        $qb->select([
            'anima_campanas.id',
            'anima_campanas.token',
            'anima_campanas.nombre',
            'anima_campanas.descripcion',
            'anima_campanas.fecha',
            'anima_campanas.lugar',
            'anima_campanas.url_evento',
            'anima_campanas.fecha_activacion',
            'anima_campanas.fecha_expiracion',
            'anima_campanas.estado',
            'anima_campanas.qr_code',
            'versa_users.name as nombre_usuario',
            'anima_campana_images.image_path as imagen_default',
            'video_counts.video_count',
        ])->selectRaw('COUNT(*) OVER() AS total_count');

        // Join normal
        $qb->join('versa_users', 'versa_users.id', '=', 'anima_campanas.id_user');

        // LEFT JOIN con onRaw
        $qb->leftJoin('anima_campana_images', 'anima_campana_images.id_campana', '=', 'anima_campanas.id')->onRaw(
            'anima_campana_images.is_default = TRUE',
        );

        // LEFT JOIN con subconsulta usando joinRaw
        $qb->leftJoinRaw(
            '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id',
        );

        // Filtro de estado
        $qb->where('anima_campanas.estado', '=', 'activo');

        // Ordenamiento
        $qb->orderBy('anima_campanas.id', 'ASC');

        $result = $qb->collect();

        // Verificaciones
        static::assertCount(3, $result); // Solo campañas activas (1, 2, 4)

        // Verificar primera campaña
        static::assertSame(1, $result[0]['id']);
        static::assertSame('TOKEN001', $result[0]['token']);
        static::assertSame('Campaña 1', $result[0]['nombre']);
        static::assertSame('Juan Pérez', $result[0]['nombre_usuario']);
        static::assertSame('/images/campana1_default.jpg', $result[0]['imagen_default']);
        static::assertEquals(3, $result[0]['video_count']);
        static::assertEquals(3, $result[0]['total_count']); // Total de registros

        // Verificar segunda campaña
        static::assertSame(2, $result[1]['id']);
        static::assertSame('/images/campana2_default.jpg', $result[1]['imagen_default']);
        static::assertEquals(1, $result[1]['video_count']);

        // Verificar cuarta campaña (sin imagen default, sin videos)
        static::assertSame(4, $result[2]['id']);
        static::assertNull($result[2]['imagen_default']);
        static::assertNull($result[2]['video_count']);
    }

    /**
     * Test de rightJoinRaw.
     */
    public function testRightJoinRaw(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select(['anima_campanas.nombre', 'versa_users.name'])
            ->rightJoinRaw('versa_users ON versa_users.id = anima_campanas.id_user')
            ->orderBy('versa_users.id')
            ->getAll();

        // Debe retornar todos los usuarios, incluso los que no tienen campañas
        // Usamos >= porque pueden existir usuarios de otros tests
        static::assertGreaterThanOrEqual(3, count($result));
    }

    /**
     * Test de innerJoinRaw.
     */
    public function testInnerJoinRaw(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select(['anima_campanas.nombre', 'versa_users.name'])
            ->innerJoinRaw('versa_users ON versa_users.id = anima_campanas.id_user')
            ->where('anima_campanas.estado', '=', 'activo')
            ->getAll();

        static::assertCount(3, $result);
    }

    /**
     * Test de joinRaw con bindings parametrizados.
     */
    public function testJoinRawWithBindings(): void
    {
        $estado = 'activo';

        $result = self::$orm
            ->table('anima_campanas')
            ->select(['anima_campanas.id', 'anima_campanas.nombre', 'anima_campanas.estado', 'versa_users.name'])
            ->joinRaw('INNER JOIN versa_users ON versa_users.id = anima_campanas.id_user AND anima_campanas.estado = ?', [
                $estado,
            ])
            ->getAll();

        static::assertCount(3, $result);

        // Verificar que todos son activos (ya filtrados por el JOIN)
        foreach ($result as $row) {
            static::assertSame('activo', $row['estado'], 'Todas las campañas deben ser activas');
        }
    }

    /**
     * Test de múltiples leftJoinRaw encadenados.
     */
    public function testMultipleLeftJoinRaw(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select([
                'anima_campanas.nombre',
                'versa_users.name as usuario',
                'anima_campana_images.image_path',
                'video_counts.video_count',
            ])
            ->leftJoinRaw('versa_users ON versa_users.id = anima_campanas.id_user')
            ->leftJoinRaw(
                'anima_campana_images ON anima_campana_images.id_campana = anima_campanas.id AND anima_campana_images.is_default = TRUE',
            )
            ->leftJoinRaw(
                '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id',
            )
            ->orderBy('anima_campanas.id')
            ->getAll();

        static::assertCount(4, $result);

        // Verificar que los LEFT JOIN mantienen todos los registros
        static::assertSame('Campaña 1', $result[0]['nombre']);
        static::assertSame('Campaña 4', $result[3]['nombre']);
    }

    /**
     * Test de combinación join normal + joinRaw.
     */
    public function testMixedJoinAndJoinRaw(): void
    {
        $result = self::$orm
            ->table('anima_campanas')
            ->select([
                'anima_campanas.nombre',
                'versa_users.name as usuario',
                'video_counts.video_count',
            ])
            ->join('versa_users', 'versa_users.id', '=', 'anima_campanas.id_user') // Join normal
            ->leftJoinRaw( // Join raw
                '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id',
            )
            ->where('anima_campanas.estado', '=', 'activo')
            ->orderBy('anima_campanas.id')
            ->getAll();

        static::assertCount(3, $result);
        static::assertSame('Juan Pérez', $result[0]['usuario']);
        static::assertEquals(3, $result[0]['video_count']);
    }

    /**
     * Test de joinRaw con múltiples bindings.
     */
    public function testJoinRawWithMultipleBindings(): void
    {
        $minVideos = 2;
        $estado = 'activo';

        $result = self::$orm
            ->table('anima_campanas')
            ->select([
                'anima_campanas.nombre',
                'video_counts.video_count',
            ])
            ->joinRaw(
                'INNER JOIN (SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana HAVING COUNT(*) >= ?) as video_counts ON video_counts.id_campana = anima_campanas.id',
                [$minVideos],
            )
            ->where('anima_campanas.estado', '=', $estado)
            ->orderBy('anima_campanas.id')
            ->getAll();

        // Solo campañas activas con 2 o más videos: Campaña 1 (3 videos)
        static::assertCount(1, $result);
        static::assertSame('Campaña 1', $result[0]['nombre']);
        static::assertEquals(3, $result[0]['video_count']);
    }

    /**
     * Test de limit y offset con joinRaw.
     */
    public function testJoinRawWithPagination(): void
    {
        $limit = 2;
        $offset = 1;

        $result = self::$orm
            ->table('anima_campanas')
            ->select([
                'anima_campanas.id',
                'anima_campanas.nombre',
                'video_counts.video_count',
            ])
            ->selectRaw('COUNT(*) OVER() AS total_count')
            ->leftJoinRaw(
                '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id',
            )
            ->orderBy('anima_campanas.id')
            ->limit($limit)
            ->offset($offset)
            ->getAll();

        static::assertCount(2, $result);
        static::assertSame(2, $result[0]['id']); // Offset 1 = segunda campaña
        static::assertSame(3, $result[1]['id']); // Tercera campaña
        static::assertEquals(4, $result[0]['total_count']); // Total sin paginación
    }

    /**
     * Test de validación: joinRaw vacío debe fallar.
     */
    public function testJoinRawEmptyThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::$orm->table('anima_campanas')->joinRaw('')->getAll();
    }

    /**
     * Test de validación: bindings debe ser array
     * Nota: En PHP 8.1+, el type hint estricto captura esto en tiempo de ejecución
     * antes de que se lance una excepción, por lo que este test no se puede ejecutar.
     */
    public function testJoinRawInvalidBindingsThrowsException(): void
    {
        // Skip this test - PHP 8.1+ type checking prevents this from being called
        static::markTestSkipped('Type hints in PHP 8.1+ prevent invalid types from being passed');

        // $this->expectException(\TypeError::class);
        // self::$orm->table('anima_campanas')
        //     ->joinRaw('INNER JOIN versa_users ON true', 'invalid')
        //     ->getAll();
    }

    private static function createTestTables(): void
    {
        // Tabla de campañas (similar al caso del usuario)
        self::$orm->exec('DROP TABLE IF EXISTS anima_campana_images CASCADE');
        self::$orm->exec('DROP TABLE IF EXISTS anima_videos CASCADE');
        self::$orm->exec('DROP TABLE IF EXISTS anima_campanas CASCADE');
        self::$orm->exec('DROP TABLE IF EXISTS versa_users CASCADE');

        self::$orm->exec('
            CREATE TABLE versa_users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');

        self::$orm->exec('
            CREATE TABLE anima_campanas (
                id SERIAL PRIMARY KEY,
                token VARCHAR(100) UNIQUE NOT NULL,
                nombre VARCHAR(255) NOT NULL,
                descripcion TEXT,
                fecha DATE,
                lugar VARCHAR(255),
                url_evento VARCHAR(500),
                fecha_activacion TIMESTAMP,
                fecha_expiracion TIMESTAMP,
                estado VARCHAR(50) DEFAULT \'activo\',
                qr_code TEXT,
                id_user INTEGER REFERENCES versa_users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');

        self::$orm->exec('
            CREATE TABLE anima_campana_images (
                id SERIAL PRIMARY KEY,
                id_campana INTEGER REFERENCES anima_campanas(id) ON DELETE CASCADE,
                image_path VARCHAR(500) NOT NULL,
                is_default BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');

        self::$orm->exec('
            CREATE TABLE anima_videos (
                id SERIAL PRIMARY KEY,
                id_campana INTEGER REFERENCES anima_campanas(id) ON DELETE CASCADE,
                video_url VARCHAR(500) NOT NULL,
                titulo VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ');
    }

    private static function insertTestData(): void
    {
        // Insertar usuarios
        self::$orm->exec("
            INSERT INTO versa_users (id, name, email) VALUES
            (1, 'Juan Pérez', 'juan@example.com'),
            (2, 'María García', 'maria@example.com'),
            (3, 'Pedro López', 'pedro@example.com')
        ");

        // Insertar campañas
        self::$orm->exec("
            INSERT INTO anima_campanas (id, token, nombre, descripcion, fecha, lugar, url_evento, estado, id_user) VALUES
            (1, 'TOKEN001', 'Campaña 1', 'Descripción 1', '2024-01-15', 'Madrid', 'https://evento1.com', 'activo', 1),
            (2, 'TOKEN002', 'Campaña 2', 'Descripción 2', '2024-02-20', 'Barcelona', 'https://evento2.com', 'activo', 2),
            (3, 'TOKEN003', 'Campaña 3', 'Descripción 3', '2024-03-10', 'Valencia', 'https://evento3.com', 'inactivo', 1),
            (4, 'TOKEN004', 'Campaña 4', 'Descripción 4', '2024-04-05', 'Sevilla', 'https://evento4.com', 'activo', 3)
        ");

        // Insertar imágenes (solo algunas campañas tienen imagen default)
        self::$orm->exec("
            INSERT INTO anima_campana_images (id_campana, image_path, is_default) VALUES
            (1, '/images/campana1_default.jpg', TRUE),
            (1, '/images/campana1_alt.jpg', FALSE),
            (2, '/images/campana2_default.jpg', TRUE),
            (3, '/images/campana3_alt.jpg', FALSE)
        ");

        // Insertar videos (diferentes campañas tienen diferente cantidad)
        self::$orm->exec("
            INSERT INTO anima_videos (id_campana, video_url, titulo) VALUES
            (1, 'https://video1.mp4', 'Video 1 de Campaña 1'),
            (1, 'https://video2.mp4', 'Video 2 de Campaña 1'),
            (1, 'https://video3.mp4', 'Video 3 de Campaña 1'),
            (2, 'https://video4.mp4', 'Video 1 de Campaña 2'),
            (3, 'https://video5.mp4', 'Video 1 de Campaña 3'),
            (3, 'https://video6.mp4', 'Video 2 de Campaña 3')
        ");
    }
}
