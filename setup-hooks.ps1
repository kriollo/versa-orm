#!/usr/bin/env pwsh
# Script de configuración de Git Hooks para VersaORM
# Instala y configura los hooks de validación de Mago

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Test,
    [switch]$Status
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "🔧 $Message" -ForegroundColor Cyan
    Write-Host ("=" * ($Message.Length + 3)) -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Test-GitRepo {
    if (-not (Test-Path ".git")) {
        Write-Error "No se encontró un repositorio Git. Ejecuta este script desde la raíz del proyecto."
        exit 1
    }
}

function Install-Hooks {
    Write-Header "Instalando Git Hooks de Validación de Formato"

    Test-GitRepo

    # Verificar que los hooks existen
    $preCommitPath = ".git/hooks/pre-commit"
    $prePushPath = ".git/hooks/pre-push"

    if (Test-Path $preCommitPath) {
        Write-Success "Hook pre-commit encontrado"
    } else {
        Write-Error "Hook pre-commit no encontrado en $preCommitPath"
        return
    }

    if (Test-Path $prePushPath) {
        Write-Success "Hook pre-push encontrado"
    } else {
        Write-Error "Hook pre-push no encontrado en $prePushPath"
        return
    }

    # En Windows, Git usa estos archivos automáticamente si existen
    Write-Success "Git Hooks instalados correctamente"

    # Verificar dependencias
    try {
        composer --version | Out-Null
        Write-Success "Composer disponible"
    } catch {
        Write-Warning "Composer no encontrado. Los hooks pueden no funcionar correctamente."
    }

    Write-Host ""
    Write-Host "🎉 Instalación completada!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Los hooks se ejecutarán automáticamente:" -ForegroundColor White
    Write-Host "  • pre-commit: Valida formato antes de cada commit" -ForegroundColor Gray
    Write-Host "  • pre-push: Validación final antes de cada push" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Para probar: " -NoNewline -ForegroundColor White
    Write-Host ".\setup-hooks.ps1 -Test" -ForegroundColor Yellow
}

function Uninstall-Hooks {
    Write-Header "Desinstalando Git Hooks"

    Test-GitRepo

    $hooks = @("pre-commit", "pre-push")

    foreach ($hook in $hooks) {
        $hookPath = ".git/hooks/$hook"
        if (Test-Path $hookPath) {
            Remove-Item $hookPath -Force
            Write-Success "Hook $hook eliminado"
        } else {
            Write-Warning "Hook $hook no encontrado"
        }
    }

    Write-Success "Git Hooks desinstalados"
}

function Test-Hooks {
    Write-Header "Probando Git Hooks"

    Test-GitRepo

    # Probar hook pre-commit
    Write-Host "🧪 Probando validación de formato..." -ForegroundColor Yellow

    try {
        # Ejecutar composer format-check
        $result = & composer format-check 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Success "Validación de formato: PASÓ"
            Write-Host "Los hooks funcionarán correctamente" -ForegroundColor Green
        } else {
            Write-Warning "Validación de formato: FALLÓ"
            Write-Host "Los hooks bloquearán commits hasta que se corrija el formato" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Para corregir, ejecuta: " -NoNewline -ForegroundColor White
            Write-Host "composer format" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Error al probar la validación: $($_.Exception.Message)"
    }
}

function Show-Status {
    Write-Header "Estado de Git Hooks"

    Test-GitRepo

    $hooks = @("pre-commit", "pre-push")

    foreach ($hook in $hooks) {
        $hookPath = ".git/hooks/$hook"
        if (Test-Path $hookPath) {
            $fileInfo = Get-Item $hookPath
            Write-Host "✅ $hook" -ForegroundColor Green
            Write-Host "   📁 Archivo: $hookPath" -ForegroundColor Gray
            Write-Host "   📅 Modificado: $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
            Write-Host "   📏 Tamaño: $($fileInfo.Length) bytes" -ForegroundColor Gray
        } else {
            Write-Host "❌ $hook (no instalado)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

# Lógica principal
if ($Install) {
    Install-Hooks
} elseif ($Uninstall) {
    Uninstall-Hooks
} elseif ($Test) {
    Test-Hooks
} elseif ($Status) {
    Show-Status
} else {
    Write-Header "Configuración de Git Hooks para VersaORM"
    Write-Host ""
    Write-Host "Uso:" -ForegroundColor White
    Write-Host "  .\setup-hooks.ps1 -Install     # Instalar/verificar hooks" -ForegroundColor Gray
    Write-Host "  .\setup-hooks.ps1 -Uninstall  # Desinstalar hooks" -ForegroundColor Gray
    Write-Host "  .\setup-hooks.ps1 -Test       # Probar funcionamiento" -ForegroundColor Gray
    Write-Host "  .\setup-hooks.ps1 -Status     # Ver estado actual" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Los hooks validarán automáticamente el formato de código PHP" -ForegroundColor Yellow
    Write-Host "usando el sistema coordinado Mago + PHP-CS-Fixer." -ForegroundColor Yellow
}
