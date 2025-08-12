# Enhanced PHPUnit Configurations

This document explains the enhanced PHPUnit configurations for VersaORM-PHP testing across different database engines.

## Overview

The enhanced configurations provide:
- **Organized test suites** by functionality and database engine
- **Comprehensive coverage reporting** with HTML, XML, and text outputs
- **Test groups** for selective test execution
- **Engine-specific optimizations** and limitations handling
- **Detailed logging** for CI/CD integration

## Configuration Files

### phpunit-mysql.xml
Enhanced configuration for MySQL/MariaDB testing with:
- **MySQL-specific test groups**: `mysql`, `fulltext`, `json`, `storage-engines`
- **Comprehensive test suites**: Core, MySQL-Specific, Advanced-SQL, Type-Mapping, etc.
- **Coverage reports**: `./tests/reports/coverage/mysql/`
- **Test logs**: `./tests/reports/mysql/`

### phpunit-postgresql.xml
Enhanced configuration for PostgreSQL testing with:
- **PostgreSQL-specific test groups**: `postgresql`, `arrays`, `jsonb`, `window-functions`, `cte`, `uuid`
- **Advanced SQL support**: CTEs, window functions, array operations
- **Coverage reports**: `./tests/reports/coverage/postgresql/`
- **Test logs**: `./tests/reports/postgresql/`

### phpunit-sqlite.xml
Enhanced configuration for SQLite testing with:
- **SQLite-aware limitations**: Excludes unsupported features
- **Workaround testing**: `limitations`, `workarounds` groups
- **Lightweight configuration**: Optimized for SQLite constraints
- **Coverage reports**: `./tests/reports/coverage/sqlite/`
- **Test logs**: `./tests/reports/sqlite/`

## Test Suites

### Core Suites (Available in all engines)
- **Core**: Basic ORM functionality (VersaORM, VersaModel, QueryBuilder)
- **Advanced-SQL**: Complex queries, subqueries, joins
- **Type-Mapping**: Data type handling and casting
- **Performance**: Caching, optimization, stress tests
- **Security**: SQL injection protection, input validation
- **Schema**: DDL operations, schema validation
- **Transactions**: Transaction handling, rollback tests
- **Validation**: Data validation, mass assignment protection
- **Batch-Operations**: Bulk operations, parameterized queries

### Engine-Specific Suites

#### MySQL-Specific
- **MySQL-Specific**: FULLTEXT search, JSON operations, storage engines
- **Relationships**: Advanced relationship handling

#### PostgreSQL-Specific
- **PostgreSQL-Specific**: Arrays, JSONB, window functions, CTEs
- **Freeze-Mode**: PostgreSQL-specific freeze mode tests

#### SQLite-Specific
- **SQLite-Specific**: REPLACE INTO, UPSERT operations with limitations

## Usage Examples

### Run all tests for a specific engine
```bash
# MySQL
php vendor/bin/phpunit --configuration phpunit-mysql.xml

# PostgreSQL
php vendor/bin/phpunit --configuration phpunit-postgresql.xml

# SQLite
php vendor/bin/phpunit --configuration phpunit-sqlite.xml
```

### Run specific test suites
```bash
# Run only core functionality tests
php vendor/bin/phpunit --configuration phpunit-mysql.xml --testsuite Core

# Run MySQL-specific features
php vendor/bin/phpunit --configuration phpunit-mysql.xml --testsuite MySQL-Specific

# Run PostgreSQL advanced SQL tests
php vendor/bin/phpunit --configuration phpunit-postgresql.xml --testsuite Advanced-SQL

# Run SQLite with limitations awareness
php vendor/bin/phpunit --configuration phpunit-sqlite.xml --testsuite SQLite-Specific
```

### Run tests by groups
```bash
# Run MySQL JSON-related tests
php vendor/bin/phpunit --configuration phpunit-mysql.xml --group json

# Run PostgreSQL array tests
php vendor/bin/phpunit --configuration phpunit-postgresql.xml --group arrays

# Run security tests across all engines
php vendor/bin/phpunit --configuration phpunit-mysql.xml --group security
```

### Generate coverage reports
```bash
# Generate HTML coverage report for MySQL
php vendor/bin/phpunit --configuration phpunit-mysql.xml --coverage-html tests/reports/coverage/mysql/html

# Generate XML coverage for CI/CD
php vendor/bin/phpunit --configuration phpunit-postgresql.xml --coverage-xml tests/reports/coverage/postgresql/xml
```

## Test Groups Reference

### Common Groups
- `core`: Basic ORM functionality
- `advanced`: Complex operations
- `performance`: Performance-related tests
- `security`: Security validation tests
- `slow`: Long-running tests (excluded by default)

### MySQL Groups
- `mysql`: MySQL-specific tests
- `fulltext`: FULLTEXT search functionality
- `json`: JSON operations
- `storage-engines`: Storage engine specific tests

### PostgreSQL Groups
- `postgresql`, `postgres`: PostgreSQL-specific tests
- `arrays`: Array data type operations
- `jsonb`: JSONB operations
- `window-functions`: Window function tests
- `cte`: Common Table Expression tests
- `uuid`: UUID data type tests
- `full-text-search`: PostgreSQL full-text search

### SQLite Groups
- `sqlite`: SQLite-specific tests
- `limitations`: Tests for SQLite limitations
- `workarounds`: Workaround implementations
- `file-based`: File-based database tests
- `in-memory`: In-memory database tests

## Coverage Reports

Each engine generates separate coverage reports:

### HTML Reports
- MySQL: `./tests/reports/coverage/mysql/html/index.html`
- PostgreSQL: `./tests/reports/coverage/postgresql/html/index.html`
- SQLite: `./tests/reports/coverage/sqlite/html/index.html`

### XML Reports (for CI/CD)
- MySQL: `./tests/reports/coverage/mysql/coverage.xml`
- PostgreSQL: `./tests/reports/coverage/postgresql/coverage.xml`
- SQLite: `./tests/reports/coverage/sqlite/coverage.xml`

### Clover Reports
- MySQL: `./tests/reports/coverage/mysql/clover.xml`
- PostgreSQL: `./tests/reports/coverage/postgresql/clover.xml`
- SQLite: `./tests/reports/coverage/sqlite/clover.xml`

## Environment Variables

Each configuration sets specific environment variables:

```php
// MySQL
DB_ENGINE=mysql
PHPUNIT_RUNNING=1
TEST_ENVIRONMENT=testing

// PostgreSQL
DB_ENGINE=postgresql
PHPUNIT_RUNNING=1
TEST_ENVIRONMENT=testing

// SQLite
DB_ENGINE=sqlite
PHPUNIT_RUNNING=1
TEST_ENVIRONMENT=testing
SQLITE_LIMITATIONS_AWARE=1
```

## CI/CD Integration

The configurations generate JUnit XML reports for CI/CD integration:
- `./tests/reports/mysql/junit.xml`
- `./tests/reports/postgresql/junit.xml`
- `./tests/reports/sqlite/junit.xml`

## Best Practices

1. **Run engine-specific tests** during development
2. **Use test suites** to focus on specific functionality
3. **Generate coverage reports** regularly to maintain quality
4. **Exclude slow tests** during rapid development cycles
5. **Use groups** for targeted testing of specific features
6. **Review logs** in `./tests/reports/` for detailed analysis

## Troubleshooting

### Common Issues

1. **Missing directories**: Ensure `./tests/reports/` structure exists
2. **Permission issues**: Check write permissions for report directories
3. **Memory limits**: Increase PHP memory limit for large test suites
4. **Database connections**: Verify database credentials in bootstrap files

### Performance Tips

1. Use specific test suites instead of running all tests
2. Exclude slow tests during development
3. Run coverage analysis separately from regular testing
4. Use in-memory SQLite for faster SQLite tests
