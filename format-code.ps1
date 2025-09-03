# Script para formatear código con Mago y php-cs-fixer sin conflictos
#
# Orden de ejecución recomendado:
# 1. php-cs-fixer: reglas de estilo PSR-12 y compatibilidad
# 2. mago fmt: mejoras adicionales de formato y legibilidad
#
# Uso: .\format-code.ps1 [ruta] [-DryRun]

[CmdletBinding()]
param(
    [string]$Path = "",
    [switch]$DryRun
)

Write-Host "🔧 Formateando código PHP con Mago y PHP-CS-Fixer" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Configurar comandos
$DryRunArg = if ($DryRun) { "--dry-run" } else { "" }

if ($Path) {
    $PhpCsCmd = "vendor\bin\php-cs-fixer fix --config=.php-cs-fixer.dist.php $DryRunArg $Path"
    $MagoCmd = "mago fmt $DryRunArg $Path"
} else {
    $PhpCsCmd = "vendor\bin\php-cs-fixer fix --config=.php-cs-fixer.dist.php $DryRunArg"
    $MagoCmd = "mago fmt $DryRunArg"
}

Write-Host ""
Write-Host "📋 Paso 1: Ejecutando PHP-CS-Fixer..." -ForegroundColor Yellow
Write-Host "Comando: $PhpCsCmd" -ForegroundColor Gray
Write-Host ""

# Ejecutar PHP-CS-Fixer
try {
    Invoke-Expression $PhpCsCmd
} catch {
    Write-Host "⚠️  PHP-CS-Fixer reportó cambios o errores" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "📋 Paso 2: Ejecutando Mago..." -ForegroundColor Yellow
Write-Host "Comando: $MagoCmd" -ForegroundColor Gray
Write-Host ""

# Ejecutar Mago
try {
    Invoke-Expression $MagoCmd
} catch {
    Write-Host "⚠️  Mago reportó cambios o errores" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✅ Formateo completado!" -ForegroundColor Green

if ($DryRun) {
    Write-Host ""
    Write-Host "🔍 Este fue un dry-run. Para aplicar los cambios ejecuta:" -ForegroundColor Cyan
    Write-Host "   .\format-code.ps1" -ForegroundColor White
    if ($Path) {
        Write-Host "   .\format-code.ps1 -Path $Path" -ForegroundColor White
    }
}
