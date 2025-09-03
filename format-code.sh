#!/usr/bin/env bash

# Script para formatear código con Mago y php-cs-fixer sin conflictos
#
# Orden de ejecución recomendado:
# 1. php-cs-fixer: reglas de estilo PSR-12 y compatibilidad
# 2. mago fmt: mejoras adicionales de formato y legibilidad
#
# Uso: ./format-code.sh [ruta] [--dry-run]

set -e

DRY_RUN=""
PATH_TARGET=""

# Procesar argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN="--dry-run"
            shift
            ;;
        *)
            PATH_TARGET="$1"
            shift
            ;;
    esac
done

echo "🔧 Formateando código PHP con Mago y PHP-CS-Fixer"
echo "=================================================="

# Configurar comando base
if [[ -n "$PATH_TARGET" ]]; then
    PHPCS_CMD="vendor/bin/php-cs-fixer fix --config=.php-cs-fixer.dist.php $DRY_RUN $PATH_TARGET"
    MAGO_CMD="mago fmt $DRY_RUN $PATH_TARGET"
else
    PHPCS_CMD="vendor/bin/php-cs-fixer fix --config=.php-cs-fixer.dist.php $DRY_RUN"
    MAGO_CMD="mago fmt $DRY_RUN"
fi

echo "📋 Paso 1: Ejecutando PHP-CS-Fixer..."
echo "Comando: $PHPCS_CMD"
echo ""

# Ejecutar PHP-CS-Fixer
if ! eval $PHPCS_CMD; then
    echo "⚠️  PHP-CS-Fixer reportó cambios o errores"
fi

echo ""
echo "📋 Paso 2: Ejecutando Mago..."
echo "Comando: $MAGO_CMD"
echo ""

# Ejecutar Mago
if ! eval $MAGO_CMD; then
    echo "⚠️  Mago reportó cambios o errores"
fi

echo ""
echo "✅ Formateo completado!"

if [[ -n "$DRY_RUN" ]]; then
    echo ""
    echo "🔍 Este fue un dry-run. Para aplicar los cambios ejecuta:"
    echo "   ./format-code.sh"
    if [[ -n "$PATH_TARGET" ]]; then
        echo "   ./format-code.sh $PATH_TARGET"
    fi
fi
