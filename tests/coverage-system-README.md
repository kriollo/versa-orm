# VersaORM Coverage System

This comprehensive coverage system provides detailed code coverage analysis for VersaORM across all database engines (MySQL, PostgreSQL, SQLite) with feature-specific tracking, gap analysis, and actionable insights.

## Features

### ✅ Complete Coverage Analysis
- **Multi-Engine Support**: Separate coverage analysis for MySQL, PostgreSQL, and SQLite
- **95% Minimum Threshold**: Enforces high coverage standards
- **Multiple Report Formats**: HTML, XML, Clover, Text, and Cobertura formats
- **Real-time Validation**: Automatic threshold validation with pass/fail status

### ✅ Feature-Based Coverage Tracking
- **Feature Mapping**: Tracks coverage for specific features (CRUD, relationships, security, etc.)
- **Cross-Engine Analysis**: Compares feature coverage across database engines
- **Gap Identification**: Identifies specific areas needing more test coverage
- **Actionable Recommendations**: Provides specific suggestions for improvement

### ✅ Advanced Reporting & Dashboards
- **Interactive HTML Dashboard**: Beautiful, responsive dashboard with charts
- **Coverage Trends**: Historical tracking and trend analysis
- **Alert System**: Automated alerts for coverage issues
- **CI/CD Integration**: JSON reports for automated pipelines

## Quick Start

### 1. Run Complete Coverage Analysis
```bash
# Analyze coverage for all engines
php tests/bin/coverage-analyze.php

# Analyze specific engine
php tests/bin/coverage-analyze.php --engine=mysql

# Generate JSON report
php tests/bin/coverage-analyze.php --format=json --output=coverage-report.json
```

### 2. Feature Coverage Analysis
```bash
# Analyze all features
php tests/bin/feature-coverage-analyze.php

# Analyze specific feature
php tests/bin/feature-coverage-analyze.php --feature=security

# Generate gaps report only
php tests/bin/feature-coverage-analyze.php --gaps-only
```

### 3. Generate Interactive Dashboard
```bash
# Generate comprehensive dashboard
php tests/bin/generate-coverage-dashboard.php

# Custom output location
php tests/bin/generate-coverage-dashboard.php --output=my-dashboard.html
```

## Coverage Requirements

### Overall Requirements
- **Minimum Coverage**: 95% across all engines
- **Critical Files**: 98% coverage for core files (VersaORM.php, VersaModel.php, QueryBuilder.php)
- **Feature Coverage**: Each feature must meet specific thresholds

### Engine-Specific Requirements
- **MySQL**: 95% minimum, includes FULLTEXT, JSON operations, storage engines
- **PostgreSQL**: 95% minimum, includes arrays, JSONB, window functions, CTEs
- **SQLite**: 90% minimum (adjusted for limitations), includes workarounds

### Feature Requirements
- **Security**: 100% coverage (critical for SQL injection protection)
- **CRUD Operations**: 98% coverage
- **Query Builder**: 96% coverage
- **Relationships**: 95% coverage
- **Transactions**: 92% coverage
- **Validation**: 94% coverage
- **Type Mapping**: 93% coverage

## File Structure

```
tests/
├── Quality/
│   ├── CoverageAnalyzer.php           # Main coverage analysis
│   ├── FeatureCoverageAnalyzer.php    # Feature-specific analysis
│   └── CoverageDashboard.php          # Dashboard generation
├── bin/
│   ├── coverage-analyze.php           # Coverage analysis runner
│   ├── feature-coverage-analyze.php   # Feature analysis runner
│   └── generate-coverage-dashboard.php # Dashboard generator
├── config/
│   └── coverage-config.php            # Coverage configuration
└── reports/coverage/
    ├── mysql/                         # MySQL coverage reports
    ├── postgresql/                    # PostgreSQL coverage reports
    ├── sqlite/                        # SQLite coverage reports
    ├── dashboard.html                 # Interactive dashboard
    ├── gaps-report.json              # Coverage gaps analysis
    └── feature-gaps-report.json      # Feature gaps analysis
```

## Configuration

The coverage system is configured via `tests/config/coverage-config.php`:

```php
return [
    'global' => [
        'minimum_coverage' => 95.0,
        'target_coverage' => 100.0,
    ],
    'engines' => [
        'mysql' => ['minimum_coverage' => 95.0],
        'postgresql' => ['minimum_coverage' => 95.0],
        'sqlite' => ['minimum_coverage' => 90.0],
    ],
    'feature_coverage' => [
        'security' => ['minimum_coverage' => 100.0],
        'crud_operations' => ['minimum_coverage' => 98.0],
        // ... more features
    ]
];
```

## PHPUnit Integration

The system enhances existing PHPUnit configurations:

### Enhanced Configurations
- **phpunit-mysql.xml**: MySQL-specific coverage with 95% threshold
- **phpunit-postgresql.xml**: PostgreSQL-specific coverage with 95% threshold
- **phpunit-sqlite.xml**: SQLite-specific coverage with 90% threshold

### Coverage Reports Generated
- **HTML Reports**: `tests/reports/coverage/{engine}/html/`
- **XML Reports**: `tests/reports/coverage/{engine}/xml/`
- **Clover Reports**: `tests/reports/coverage/{engine}/clover.xml`
- **Text Reports**: `tests/reports/coverage/{engine}/coverage.txt`

## Alert System

The system generates alerts for:

### Coverage Alerts
- Coverage below minimum threshold
- Critical files with insufficient coverage
- Coverage regression detection
- Missing test files

### Feature Alerts
- Features below required coverage
- Engine-specific feature gaps
- Critical feature coverage issues

### Alert Severities
- **Critical**: Immediate attention required
- **High**: Should be addressed soon
- **Medium**: Moderate priority
- **Low**: Minor improvements

## CI/CD Integration

### GitHub Actions Integration
```yaml
- name: Run Coverage Analysis
  run: |
    php tests/bin/coverage-analyze.php --format=json --output=coverage.json
    php tests/bin/feature-coverage-analyze.php --format=json --output=features.json

- name: Generate Dashboard
  run: php tests/bin/generate-coverage-dashboard.php

- name: Check Coverage Threshold
  run: |
    COVERAGE=$(php tests/bin/coverage-analyze.php --format=json | jq '.score')
    if [ "$COVERAGE" -lt 95 ]; then
      echo "Coverage $COVERAGE% is below minimum 95%"
      exit 1
    fi
```

### JSON Output Format
```json
{
  "tool": "coverage",
  "score": 96.5,
  "passed": true,
  "issues": [],
  "metrics": {
    "overall_coverage": 96.5,
    "engine_results": {
      "mysql": {"coverage_percentage": 97.2},
      "postgresql": {"coverage_percentage": 96.8},
      "sqlite": {"coverage_percentage": 95.5}
    }
  }
}
```

## Advanced Features

### Gap Analysis
Identifies specific files and lines that need more coverage:
```bash
php tests/bin/coverage-analyze.php --gaps-only
```

### Trend Analysis
Tracks coverage changes over time:
- Historical coverage data
- Regression detection
- Improvement tracking

### Feature Mapping
Maps test files to specific features:
- CRUD operations → VersaORMTest.php files
- Security → SecurityTest.php files
- Relationships → RelationshipsTest.php files

## Best Practices

### Writing Tests for Coverage
1. **Test All Code Paths**: Ensure every branch is tested
2. **Edge Cases**: Test boundary conditions and error scenarios
3. **Engine-Specific Features**: Test database-specific functionality
4. **Integration Tests**: Test feature interactions

### Maintaining High Coverage
1. **Pre-commit Hooks**: Run coverage checks before commits
2. **Regular Monitoring**: Check dashboard regularly
3. **Address Gaps Quickly**: Fix coverage gaps as soon as identified
4. **Feature-First Testing**: Write tests when adding new features

### Performance Optimization
1. **Parallel Execution**: Run engine tests in parallel
2. **Incremental Analysis**: Only analyze changed files when possible
3. **Caching**: Cache coverage data for faster subsequent runs

## Troubleshooting

### Common Issues

#### Coverage Data Not Found
```bash
# Generate coverage first
php vendor/bin/phpunit --configuration=phpunit-mysql.xml --coverage-clover=tests/reports/coverage/mysql/clover.xml
```

#### PHPUnit Not Found
```bash
# Install dependencies
composer install

# Or use global PHPUnit
composer global require phpunit/phpunit
```

#### Permission Issues
```bash
# Fix permissions
chmod +x tests/bin/*.php
mkdir -p tests/reports/coverage/{mysql,postgresql,sqlite}
```

### Debug Mode
Enable detailed logging:
```bash
php tests/bin/coverage-analyze.php --debug
```

## Contributing

When adding new features:
1. Add feature definition to `coverage-config.php`
2. Create corresponding test files
3. Update feature mapping in `FeatureCoverageAnalyzer.php`
4. Ensure minimum coverage thresholds are met

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review log files in `tests/logs/`
3. Run with `--debug` flag for detailed output
4. Check dashboard alerts for specific guidance

---

**Goal**: Achieve and maintain 100% code coverage across all database engines while ensuring comprehensive feature testing and continuous quality improvement.
