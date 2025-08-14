# VersaORM QA Tools Makefile
# Integrated execution of all QA tools in the correct order

.PHONY: help qa qa-fix qa-check rector rector-fix cs cs-fix phpstan psalm phpunit test clean cache-clear

# Default target
help: ## Show this help message
	@echo "VersaORM QA Tools"
	@echo "=================="
	@echo ""
	@echo "Integrated QA tools execution in the correct order to avoid conflicts:"
	@echo "1. Rector (code modernization)"
	@echo "2. PHP-CS-Fixer (code style)"
	@echo "3. PHPStan (static analysis)"
	@echo "4. Psalm (security analysis)"
	@echo "5. PHPUnit (tests)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Main QA targets
qa: ## Run all QA tools in check mode (recommended)
	@echo "🔍 Running all QA tools in check mode..."
	@php qa-integration.php

qa-fix: ## Run all QA tools and apply fixes automatically
	@echo "🔧 Running all QA tools with automatic fixes..."
	@php qa-integration.php --fix

qa-check: qa ## Alias for qa (check mode)

# Individual tool targets
rector: ## Run Rector in check mode
	@echo "🔍 Running Rector (check mode)..."
	@vendor/bin/rector process --dry-run

rector-fix: ## Run Rector and apply changes
	@echo "🔧 Running Rector (fix mode)..."
	@vendor/bin/rector process

cs: ## Run PHP-CS-Fixer in check mode
	@echo "🔍 Running PHP-CS-Fixer (check mode)..."
	@vendor/bin/php-cs-fixer fix --dry-run --diff

cs-fix: ## Run PHP-CS-Fixer and apply fixes
	@echo "🔧 Running PHP-CS-Fixer (fix mode)..."
	@vendor/bin/php-cs-fixer fix

phpstan: ## Run PHPStan static analysis
	@echo "🔍 Running PHPStan..."
	@vendor/bin/phpstan analyse --memory-limit=512M

psalm: ## Run Psalm security analysis
	@echo "🔍 Running Psalm..."
	@vendor/bin/psalm --show-info=false

# Testing targets
phpunit: ## Run PHPUnit tests (SQLite)
	@echo "🧪 Running PHPUnit tests (SQLite)..."
	@vendor/bin/phpunit

test: phpunit ## Alias for phpunit

test-mysql: ## Run PHPUnit tests (MySQL)
	@echo "🧪 Running PHPUnit tests (MySQL)..."
	@vendor/bin/phpunit -c phpunit-mysql.xml

test-postgresql: ## Run PHPUnit tests (PostgreSQL)
	@echo "🧪 Running PHPUnit tests (PostgreSQL)..."
	@vendor/bin/phpunit -c phpunit-postgresql.xml

test-sqlite: ## Run PHPUnit tests (SQLite)
	@echo "🧪 Running PHPUnit tests (SQLite)..."
	@vendor/bin/phpunit -c phpunit-sqlite.xml

test-all: ## Run tests for all database engines
	@echo "🧪 Running tests for all database engines..."
	@$(MAKE) test-sqlite
	@$(MAKE) test-mysql
	@$(MAKE) test-postgresql

# Selective QA targets
qa-rector: ## Run only Rector
	@php qa-integration.php --only=rector

qa-cs: ## Run only PHP-CS-Fixer
	@php qa-integration.php --only=php-cs-fixer

qa-phpstan: ## Run only PHPStan
	@php qa-integration.php --only=phpstan

qa-psalm: ## Run only Psalm
	@php qa-integration.php --only=psalm

qa-no-psalm: ## Run QA tools except Psalm
	@php qa-integration.php --skip=psalm

qa-no-rector: ## Run QA tools except Rector
	@php qa-integration.php --skip=rector

# Maintenance targets
clean: ## Clean all cache and temporary files
	@echo "🧹 Cleaning cache and temporary files..."
	@rm -rf var/cache/*
	@rm -rf tests/reports/*
	@rm -f .php-cs-fixer.cache
	@rm -f .phpunit.result.cache
	@echo "✅ Cache cleaned"

cache-clear: clean ## Alias for clean

# Development workflow targets
dev-check: ## Quick development check (Rector + CS + PHPStan)
	@echo "🚀 Quick development check..."
	@php qa-integration.php --skip=psalm

dev-fix: ## Quick development fix (Rector + CS fixes)
	@echo "🚀 Quick development fix..."
	@php qa-integration.php --only=rector,php-cs-fixer --fix

pre-commit: ## Pre-commit checks (all tools in check mode)
	@echo "🔍 Pre-commit checks..."
	@$(MAKE) qa

pre-push: ## Pre-push checks (all tools + tests)
	@echo "🔍 Pre-push checks..."
	@$(MAKE) qa
	@$(MAKE) test

ci: ## CI pipeline (all checks + all tests)
	@echo "🤖 CI Pipeline..."
	@$(MAKE) qa
	@$(MAKE) test-all

# Information targets
config: ## Show current QA configuration
	@echo "📋 QA Tools Configuration:"
	@echo "=========================="
	@echo "Rector config:     rector.php"
	@echo "PHP-CS-Fixer:     .php-cs-fixer.dist.php"
	@echo "PHPStan config:    phpstan.neon"
	@echo "Psalm config:      psalm.xml"
	@echo "PHPUnit configs:   phpunit*.xml"
	@echo "Integration:       qa-integration.php"
	@echo "Cache directory:   var/cache/"
	@echo "Reports directory: tests/reports/"

status: ## Show QA tools status
	@echo "📊 QA Tools Status:"
	@echo "==================="
	@echo -n "Rector:      "; [ -f vendor/bin/rector ] && echo "✅ Available" || echo "❌ Missing"
	@echo -n "PHP-CS-Fixer: "; [ -f vendor/bin/php-cs-fixer ] && echo "✅ Available" || echo "❌ Missing"
	@echo -n "PHPStan:     "; [ -f vendor/bin/phpstan ] && echo "✅ Available" || echo "❌ Missing"
	@echo -n "Psalm:       "; [ -f vendor/bin/psalm ] && echo "✅ Available" || echo "❌ Missing"
	@echo -n "PHPUnit:     "; [ -f vendor/bin/phpunit ] && echo "✅ Available" || echo "❌ Missing"

# Verbose mode targets
qa-verbose: ## Run all QA tools with verbose output
	@php qa-integration.php --verbose

qa-fix-verbose: ## Run all QA tools with fixes and verbose output
	@php qa-integration.php --fix --verbose
