@echo off
SETLOCAL EnableDelayedExpansion

echo Cleaning previous coverage parts...
if existent "build\coverage\parts" del /q build\coverage\parts\*

echo Running SQLite Tests...
vendor\bin\phpunit --configuration phpunit.xml --coverage-php build\coverage\parts\sqlite.cov

echo Running MySQL Tests...
@putenv DB_DRIVER=mysql
@putenv DB_HOST=localhost
@putenv DB_PORT=3306
@putenv DB_NAME=versaorm_test
@putenv DB_USER=local
@putenv DB_PASS=local
vendor\bin\phpunit --configuration phpunit-mysql.xml --coverage-php build\coverage\parts\mysql.cov

echo Running PostgreSQL Tests...
@putenv DB_DRIVER=postgresql
@putenv DB_HOST=localhost
@putenv DB_PORT=5432
@putenv DB_NAME=versaorm_test
@putenv DB_USER=local
@putenv DB_PASS=local
vendor\bin\phpunit --configuration phpunit-postgresql.xml --coverage-php build\coverage\parts\postgresql.cov

echo Merging reports...
php scripts\merge-coverage.php
