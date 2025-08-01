@echo off
setlocal

set PROJECT_DIR=%~dp0
set BINARY_NAME=versaorm_cli
set OUTPUT_DIR=src\binary

echo ---------------------------------------
echo Compilando para Windows (x86_64-pc-windows-msvc)...
echo ---------------------------------------
cargo build --release --target x86_64-pc-windows-msvc
IF EXIST "%PROJECT_DIR%target\x86_64-pc-windows-msvc\release\%BINARY_NAME%.exe" (
    echo ✅ Windows: binario generado exitosamente.
    IF NOT EXIST "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
    copy /Y "%PROJECT_DIR%target\x86_64-pc-windows-msvc\release\%BINARY_NAME%.exe" "%OUTPUT_DIR%\%BINARY_NAME%_windows.exe"
) ELSE (
    echo ❌ Windows: no se generó el ejecutable.
)

echo ---------------------------------------
echo Compilando para Linux (x86_64-unknown-linux-gnu)...
echo ---------------------------------------
cross build --release --target x86_64-unknown-linux-gnu
IF EXIST "%PROJECT_DIR%target\x86_64-unknown-linux-gnu\release\%BINARY_NAME%" (
    echo ✅ Linux: binario generado exitosamente.
    IF NOT EXIST "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
    copy /Y "%PROJECT_DIR%target\x86_64-unknown-linux-gnu\release\%BINARY_NAME%" "%OUTPUT_DIR%\%BINARY_NAME%_linux"
) ELSE (
    echo ❌ Linux: no se generó el binario.
)

echo ---------------------------------------
echo 🟢 Proceso de compilación finalizado. Verifica errores si los hubo.
echo ---------------------------------------
pause
