# Script para ejecutar tests de PostgreSQL con la configuración correcta

$env:XDEBUG_MODE="off"
$env:DB_DRIVER="postgresql"
$env:DB_HOST="localhost"
$env:DB_PORT="5432"
$env:DB_NAME="versaorm_test"
$env:DB_USER="local"
$env:DB_PASS="local"

Write-Host "🐘 Ejecutando tests de PostgreSQL..." -ForegroundColor Green
Write-Host "Configuración:" -ForegroundColor Yellow
Write-Host "  Driver: $env:DB_DRIVER" -ForegroundColor Cyan
Write-Host "  Host: $env:DB_HOST" -ForegroundColor Cyan
Write-Host "  Port: $env:DB_PORT" -ForegroundColor Cyan
Write-Host "  Database: $env:DB_NAME" -ForegroundColor Cyan
Write-Host "  User: $env:DB_USER" -ForegroundColor Cyan
Write-Host ""

php vendor/bin/phpunit --configuration=phpunit-postgresql.xml --testdox
