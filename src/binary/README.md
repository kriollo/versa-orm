# VersaORM Binaries

Esta carpeta contiene los binarios compilados de VersaORM para diferentes sistemas operativos.

## Estructura de archivos

Los binarios deben seguir la siguiente nomenclatura:

- `versaorm_cli_windows.exe` - Binario para Windows
- `versaorm_cli_linux` - Binario para Linux
- `versaorm_cli_darwin` - Binario para macOS

## Compilación

Para compilar un nuevo binario:

1. Navega al directorio `versaorm_cli/`
2. Ejecuta `cargo build --release`
3. Copia el binario resultante a esta carpeta con el nombre apropiado

### Windows
```bash
cd versaorm_cli
cargo build --release
copy target\release\versaorm_cli.exe ..\src\binary\versaorm_cli_windows.exe
```

### Linux/macOS
```bash
cd versaorm_cli
cargo build --release
cp target/release/versaorm_cli ../src/binary/versaorm_cli_linux
# o para macOS:
cp target/release/versaorm_cli ../src/binary/versaorm_cli_darwin
```

## Detección automática

VersaORM detecta automáticamente el sistema operativo y usa el binario apropiado:

- `PHP_OS_FAMILY === 'Windows'` → `versaorm_cli_windows.exe`
- `PHP_OS_FAMILY === 'Linux'` → `versaorm_cli_linux`
- `PHP_OS_FAMILY === 'Darwin'` → `versaorm_cli_darwin`

## Notas

- Los binarios deben tener permisos de ejecución en sistemas Unix
- Asegúrate de que los binarios sean compatibles con la arquitectura del sistema objetivo
- Esta carpeta debe estar incluida en el control de versiones para distribución
