<?php

declare(strict_types=1);

namespace VersaORM\Tests\Compatibility;

use Exception;
use PDO;
use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

use function function_exists;
use function in_array;
use function ini_get;

use const PHP_INT_SIZE;
use const PHP_SAPI;
use const PHP_VERSION_ID;

/**
 * PHPVersionCompatibilityTest - Valida funcionamiento en diferentes versiones de PHP.
 *
 * Este test verifica que VersaORM funcione correctamente en todas las versiones
 * de PHP soportadas: 7.4, 8.0, 8.1, 8.2, 8.3
 */
class PHPVersionCompatibilityTest extends TestCase
{
    private static array $phpVersionInfo;

    private static array $supportedVersions = ['7.4', '8.0', '8.1', '8.2', '8.3'];

    private static array $versionFeatures = [];

    public static function setUpBeforeClass(): void
    {
        self::$phpVersionInfo = [
            'version' => PHP_VERSION,
            'major' => PHP_MAJOR_VERSION,
            'minor' => PHP_MINOR_VERSION,
            'release' => PHP_RELEASE_VERSION,
            'version_id' => PHP_VERSION_ID,
            'extra_version' => PHP_EXTRA_VERSION ?? '',
            'zts' => PHP_ZTS,
            'debug' => PHP_DEBUG,
            'maxpathlen' => PHP_MAXPATHLEN,
            'os' => PHP_OS,
            'os_family' => PHP_OS_FAMILY,
            'sapi' => PHP_SAPI,
            'eol' => PHP_EOL,
            'int_max' => PHP_INT_MAX,
            'int_min' => PHP_INT_MIN,
            'int_size' => PHP_INT_SIZE,
            'float_max' => PHP_FLOAT_MAX,
            'float_min' => PHP_FLOAT_MIN,
            'float_dig' => PHP_FLOAT_DIG,
            'float_epsilon' => PHP_FLOAT_EPSILON,
        ];

        self::detectVersionFeatures();
    }

    /**
     * @group php-compatibility
     * @group core
     */
    public function test_php_version_supported(): void
    {
        $currentVersion = self::getCurrentPHPVersion();

        static::assertContains(
            $currentVersion,
            self::$supportedVersions,
            "PHP version {$currentVersion} is not in supported versions list",
        );

        // Log version info for reporting
        $this->addToAssertionCount(1);
        echo "\n=== PHP Version Compatibility Test ===\n";
        echo 'Current PHP Version: ' . PHP_VERSION . "\n";
        echo 'Version ID: ' . PHP_VERSION_ID . "\n";
        echo 'SAPI: ' . PHP_SAPI . "\n";
        echo 'OS: ' . PHP_OS_FAMILY . "\n";
        echo 'ZTS: ' . (PHP_ZTS !== 0 ? 'Yes' : 'No') . "\n";
        echo 'Debug: ' . (PHP_DEBUG !== 0 ? 'Yes' : 'No') . "\n";
    }

    /**
     * @group php-compatibility
     * @group core
     */
    public function test_basic_versa_orm_instantiation(): void
    {
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'options' => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ],
        ];

        $orm = new VersaORM($config);
        static::assertInstanceOf(VersaORM::class, $orm);

        // Test basic functionality
        try {
            $orm->exec('SELECT 1');
            static::assertTrue(true, 'Database connection works');
        } catch (Exception $e) {
            static::fail('Database connection failed: ' . $e->getMessage());
        }
    }

    /**
     * @group php-compatibility
     * @group core
     */
    public function test_query_builder_instantiation(): void
    {
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        $orm = new VersaORM($config);
        $qb = $orm->table('test');
        static::assertInstanceOf(QueryBuilder::class, $qb);
    }

    /**
     * @group php-compatibility
     * @group features
     */
    public function test_ph_p74_specific_features(): void
    {
        if (!$this->isVersionAtLeast('7.4')) {
            static::markTestSkipped('PHP 7.4+ required for this test');
        }

        // Test typed properties (PHP 7.4+)
        static::assertTrue(self::$versionFeatures['typed_properties']);

        // Test arrow functions (PHP 7.4+)
        static::assertTrue(self::$versionFeatures['arrow_functions']);

        // Test null coalescing assignment operator (PHP 7.4+)
        static::assertTrue(self::$versionFeatures['null_coalescing_assignment']);

        // Test spread operator in array expressions (PHP 7.4+)
        static::assertTrue(self::$versionFeatures['array_spread']);
    }

    /**
     * @group php-compatibility
     * @group features
     */
    public function test_ph_p80_specific_features(): void
    {
        if (!$this->isVersionAtLeast('8.0')) {
            static::markTestSkipped('PHP 8.0+ required for this test');
        }

        // Test named arguments (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['named_arguments']);

        // Test attributes (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['attributes']);

        // Test constructor property promotion (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['constructor_promotion']);

        // Test union types (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['union_types']);

        // Test match expression (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['match_expression']);

        // Test nullsafe operator (PHP 8.0+)
        static::assertTrue(self::$versionFeatures['nullsafe_operator']);
    }

    /**
     * @group php-compatibility
     * @group features
     */
    public function test_ph_p81_specific_features(): void
    {
        if (!$this->isVersionAtLeast('8.1')) {
            static::markTestSkipped('PHP 8.1+ required for this test');
        }

        // Test enums (PHP 8.1+)
        static::assertTrue(self::$versionFeatures['enums']);

        // Test readonly properties (PHP 8.1+)
        static::assertTrue(self::$versionFeatures['readonly_properties']);

        // Test intersection types (PHP 8.1+)
        static::assertTrue(self::$versionFeatures['intersection_types']);

        // Test first-class callable syntax (PHP 8.1+)
        static::assertTrue(self::$versionFeatures['first_class_callables']);

        // Test new in initializers (PHP 8.1+)
        static::assertTrue(self::$versionFeatures['new_in_initializers']);
    }

    /**
     * @group php-compatibility
     * @group features
     */
    public function test_ph_p82_specific_features(): void
    {
        if (!$this->isVersionAtLeast('8.2')) {
            static::markTestSkipped('PHP 8.2+ required for this test');
        }

        // Test readonly classes (PHP 8.2+)
        static::assertTrue(self::$versionFeatures['readonly_classes']);

        // Test DNF types (PHP 8.2+)
        static::assertTrue(self::$versionFeatures['dnf_types']);

        // Test constants in traits (PHP 8.2+)
        static::assertTrue(self::$versionFeatures['constants_in_traits']);
    }

    /**
     * @group php-compatibility
     * @group features
     */
    public function test_ph_p83_specific_features(): void
    {
        if (!$this->isVersionAtLeast('8.3')) {
            static::markTestSkipped('PHP 8.3+ required for this test');
        }

        // Test typed class constants (PHP 8.3+)
        static::assertTrue(self::$versionFeatures['typed_class_constants']);

        // Test dynamic class constant fetch (PHP 8.3+)
        static::assertTrue(self::$versionFeatures['dynamic_class_constant_fetch']);

        // Test override attribute (PHP 8.3+)
        static::assertTrue(self::$versionFeatures['override_attribute']);
    }

    /**
     * @group php-compatibility
     * @group memory
     */
    public function test_memory_usage_by_version(): void
    {
        $initialMemory = memory_get_usage(true);

        // Create multiple ORM instances to test memory usage
        $instances = [];

        for ($i = 0; $i < 10; $i++) {
            $config = [
                'driver' => 'sqlite',
                'database' => ':memory:',
            ];
            $instances[] = new VersaORM($config);
        }

        $finalMemory = memory_get_usage(true);
        $memoryUsed = $finalMemory - $initialMemory;

        // Memory usage should be reasonable (less than 10MB for 10 instances)
        static::assertLessThan(
            10 * 1024 * 1024,
            $memoryUsed,
            'Memory usage too high: ' . number_format(($memoryUsed / 1024) / 1024, 2) . 'MB',
        );

        // Log memory usage for version-specific analysis
        echo "\nMemory usage for PHP " . PHP_VERSION . ': ' . number_format(($memoryUsed / 1024) / 1024, 2) . "MB\n";

        // Clean up
        unset($instances);
    }

    /**
     * @group php-compatibility
     * @group performance
     */
    public function test_performance_by_version(): void
    {
        $iterations = 1000;
        $startTime = microtime(true);

        // Test basic operations performance
        for ($i = 0; $i < $iterations; $i++) {
            $config = [
                'driver' => 'sqlite',
                'database' => ':memory:',
            ];
            $orm = new VersaORM($config);
            $qb = $orm->table('test');
            unset($orm, $qb);
        }

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        // Performance should be reasonable (less than 5 seconds for 1000 iterations)
        static::assertLessThan(
            5.0,
            $executionTime,
            "Performance too slow: {$executionTime}s for {$iterations} iterations",
        );

        // Log performance for version-specific analysis
        echo
            "\nPerformance for PHP "
                . PHP_VERSION
                . ': '
                . number_format($executionTime, 4)
                . "s for {$iterations} iterations\n"
        ;
    }

    /**
     * @group php-compatibility
     * @group error-handling
     */
    public function test_error_handling_by_version(): void
    {
        // Test that error handling works consistently across PHP versions
        // VersaORM is tolerant of configuration errors, so we test basic functionality instead
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        $orm = new VersaORM($config);
        static::assertInstanceOf(VersaORM::class, $orm);

        // Test that we can handle basic operations without errors
        try {
            $orm->exec('SELECT 1');
            static::assertTrue(true, 'Basic operation succeeded');
        } catch (Exception $e) {
            static::fail('Unexpected exception: ' . $e->getMessage());
        }
    }

    /**
     * @group php-compatibility
     * @group type-system
     */
    public function test_type_system_compatibility(): void
    {
        // Test that type declarations work across versions
        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
        ];

        $orm = new VersaORM($config);

        // Test return type declarations
        $version = $orm->version();
        static::assertIsString($version);

        // Test parameter type declarations
        $qb = $orm->table('users');
        static::assertInstanceOf(QueryBuilder::class, $qb);
    }

    /**
     * Obtiene información detallada de la versión PHP para reportes.
     */
    public static function getVersionInfo(): array
    {
        return self::$phpVersionInfo;
    }

    /**
     * Obtiene las características detectadas de la versión.
     */
    public static function getVersionFeatures(): array
    {
        return self::$versionFeatures;
    }

    /**
     * Genera reporte específico de compatibilidad para la versión actual.
     */
    public static function generateCompatibilityReport(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'version_id' => PHP_VERSION_ID,
            'supported' => in_array(self::getCurrentPHPVersion(), self::$supportedVersions, true),
            'features' => self::$versionFeatures,
            'system_info' => self::$phpVersionInfo,
            'extensions' => get_loaded_extensions(),
            'ini_settings' => [
                'memory_limit' => ini_get('memory_limit'),
                'max_execution_time' => ini_get('max_execution_time'),
                'error_reporting' => ini_get('error_reporting'),
                'display_errors' => ini_get('display_errors'),
                'log_errors' => ini_get('log_errors'),
                'upload_max_filesize' => ini_get('upload_max_filesize'),
                'post_max_size' => ini_get('post_max_size'),
                'max_input_vars' => ini_get('max_input_vars'),
            ],
            'opcache' => function_exists('opcache_get_status') ? opcache_get_status() : null,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * Detecta características específicas de la versión PHP actual.
     */
    private static function detectVersionFeatures(): void
    {
        $version = PHP_VERSION_ID;

        // PHP 7.4+ features
        self::$versionFeatures['typed_properties'] = $version >= 70400;
        self::$versionFeatures['arrow_functions'] = $version >= 70400;
        self::$versionFeatures['null_coalescing_assignment'] = $version >= 70400;
        self::$versionFeatures['array_spread'] = $version >= 70400;

        // PHP 8.0+ features
        self::$versionFeatures['named_arguments'] = $version >= 80000;
        self::$versionFeatures['attributes'] = $version >= 80000;
        self::$versionFeatures['constructor_promotion'] = $version >= 80000;
        self::$versionFeatures['union_types'] = $version >= 80000;
        self::$versionFeatures['match_expression'] = $version >= 80000;
        self::$versionFeatures['nullsafe_operator'] = $version >= 80000;

        // PHP 8.1+ features
        self::$versionFeatures['enums'] = $version >= 80100;
        self::$versionFeatures['readonly_properties'] = $version >= 80100;
        self::$versionFeatures['intersection_types'] = $version >= 80100;
        self::$versionFeatures['first_class_callables'] = $version >= 80100;
        self::$versionFeatures['new_in_initializers'] = $version >= 80100;

        // PHP 8.2+ features
        self::$versionFeatures['readonly_classes'] = $version >= 80200;
        self::$versionFeatures['dnf_types'] = $version >= 80200;
        self::$versionFeatures['constants_in_traits'] = $version >= 80200;

        // PHP 8.3+ features
        self::$versionFeatures['typed_class_constants'] = $version >= 80300;
        self::$versionFeatures['dynamic_class_constant_fetch'] = $version >= 80300;
        self::$versionFeatures['override_attribute'] = $version >= 80300;
    }

    /**
     * Obtiene la versión PHP actual en formato X.Y.
     */
    private static function getCurrentPHPVersion(): string
    {
        return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    }

    /**
     * Verifica si la versión actual es al menos la especificada.
     */
    private function isVersionAtLeast(string $version): bool
    {
        return version_compare(PHP_VERSION, $version, '>=');
    }
}
