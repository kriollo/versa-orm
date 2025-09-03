<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class VersaORMHelpersTest extends TestCase
{
    public function testDropIndexPortableForDrivers(): void
    {
        $drivers = [
            'mysql' => 'ALTER TABLE `users` DROP INDEX `idx_name`',
            'sqlite' => 'DROP INDEX IF EXISTS "idx_name"',
            'postgresql' => 'DROP INDEX IF EXISTS "idx_name"',
        ];

        foreach ($drivers as $driver => $expectedSql) {
            $config = ['driver' => $driver, 'debug' => false];

            $mock = $this->getMockBuilder(VersaORM::class)
                ->setConstructorArgs([$config])
                ->onlyMethods(['exec'])
                ->getMock();

            $mock->expects($this->once())->method('exec')->with(static::equalTo($expectedSql));

            // Invocar método privado
            $this->invokePrivate($mock, 'dropIndexPortable', ['users', 'idx_name', $driver]);
        }
    }

    public function testBuildDetailedAndSimpleErrorMessagesIncludeExpectedParts(): void
    {
        $orm = new VersaORM([]);

        $detailed = $this->invokePrivate($orm, 'buildDetailedErrorMessage', [
            'E_CODE',
            'Connection refused',
            ['detail' => 'socket error'],
            '08001',
            'raw',
            'SELECT 1',
            [1, 2],
        ]);

        static::assertStringContainsString('VersaORM Error [E_CODE]: Connection refused', $detailed);
        static::assertStringContainsString('Query: SELECT 1', $detailed);
        static::assertStringContainsString('Bindings:', $detailed);
        static::assertStringContainsString('SQL State: 08001', $detailed);
        static::assertStringContainsString('Suggestions:', $detailed);

        $simple = $this->invokePrivate($orm, 'buildSimpleErrorMessage', ['E2', 'Bad things']);
        static::assertSame('Database Error [E2]: Bad things', $simple);
    }

    public function testLogErrorWritesFileAndCleanOldLogsRemovesOld(): void
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'versaorm_logs_' . uniqid();
        if (!mkdir($tmp) && !is_dir($tmp)) {
            static::markTestSkipped('Could not create temp dir for logs');
        }

        $config = ['debug' => true, 'log_path' => $tmp];
        $orm = new VersaORM($config);

        // Ensure no log exists yet
        $todayFile = $tmp . DIRECTORY_SEPARATOR . 'php-' . date('Y-m-d') . '.log';
        if (file_exists($todayFile)) {
            unlink($todayFile);
        }

        // Invoke logError (private)
        $this->invokePrivate($orm, 'logError', ['E100', 'Test error', 'SELECT 1', ['a' => 'b'], 'Full message']);

        static::assertFileExists($todayFile);
        $content = file_get_contents($todayFile);
        static::assertStringContainsString('[ERROR] [E100] Test error', $content);
        static::assertStringContainsString('SELECT 1', $content);

        // Create an old log file and assert cleanOldLogs removes it
        $oldDate = date('Y-m-d', strtotime('-10 days'));
        $oldFile = $tmp . DIRECTORY_SEPARATOR . $oldDate . '.log';
        file_put_contents($oldFile, "old\n");
        static::assertFileExists($oldFile);

        $this->invokePrivate($orm, 'cleanOldLogs', [$tmp]);

        // old file should be removed
        static::assertFileDoesNotExist($oldFile);

        // Cleanup
        @unlink($todayFile);
        @rmdir($tmp);
    }

    public function testGetErrorSuggestionsFindsRelevantHints(): void
    {
        $orm = new VersaORM([]);

        $sug1 = $this->invokePrivate($orm, 'getErrorSuggestions', ['Connection failed: timeout']);
        static::assertIsArray($sug1);
        static::assertContains('Check database server is running', $sug1);

        $sug2 = $this->invokePrivate($orm, 'getErrorSuggestions', ['Table users not found']);
        static::assertContains('Check if the table name is spelled correctly', $sug2);
    }

    private function invokePrivate(object $obj, string $method, array $args = [])
    {
        $ref = new \ReflectionMethod($obj, $method);
        $ref->setAccessible(true);

        return $ref->invokeArgs($obj, $args);
    }
}
