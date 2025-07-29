# Configuración del Entorno de Desarrollo

Si quieres contribuir a VersaORM, lo primero es configurar un entorno de desarrollo local que te permita modificar tanto el código PHP como el código Rust, y verificar que tus cambios no rompen nada.

## Requisitos Previos

Necesitarás tener instalado el siguiente software en tu sistema:

1.  **PHP:** Versión 7.4 o superior.
2.  **Composer:** El gestor de dependencias para PHP. [Instrucciones de instalación](https://getcomposer.org/download/).
3.  **Rust:** El compilador y gestor de paquetes para Rust. La forma más fácil de instalarlo es a través de `rustup`. [Instrucciones de instalación](https://www.rust-lang.org/tools/install).
4.  **Git:** El sistema de control de versiones. [Instrucciones de instalación](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).
5.  **Una base de datos local:** Una instancia de MySQL, PostgreSQL o SQLite para ejecutar las pruebas.

---

## Pasos para la Configuración

### 1. Clonar el Repositorio

Primero, clona el repositorio oficial de VersaORM desde GitHub a tu máquina local.

```bash
git clone https://github.com/kriollo/versa-orm.git
cd versa-orm
```

### 2. Instalar Dependencias de PHP

El proyecto utiliza Composer para gestionar las dependencias de PHP (como PHPUnit para las pruebas). Ejecuta el siguiente comando en la raíz del proyecto:

```bash
composer install
```

Esto creará una carpeta `vendor/` con todas las bibliotecas necesarias.

### 3. Compilar el Núcleo de Rust

El corazón del ORM es el binario de Rust. Necesitas compilarlo desde el código fuente para que la capa de PHP pueda usarlo. Afortunadamente, el proceso es muy sencillo gracias a Cargo, el gestor de paquetes de Rust.

Navega al directorio de la CLI y compila el proyecto en modo de "release" (optimizado):

```bash
cd versaorm_cli
cargo build --release
cd ..
```

Este comando hará dos cosas:

-   Descargará todas las dependencias de Rust (definidas en `Cargo.toml`).
-   Compilará el binario y lo dejará en el directorio `versaorm_cli/target/release/`.

El binario se llamará `versaorm_cli` en Linux/macOS y `versaorm_cli.exe` en Windows.

### 4. Copiar el Binario Compilado

La capa de PHP espera encontrar el binario en el directorio `src/binary/`. Debes copiar el binario que acabas de compilar a esa ubicación. **Este es un paso crucial.**

**En Linux o macOS:**
```bash
cp versaorm_cli/target/release/versaorm_cli src/binary/versaorm_cli_linux
```
*(Si estás en macOS, copia a `versaorm_cli_darwin`)*

**En Windows (usando Command Prompt):**
```bash
copy versaorm_cli\target\release\versaorm_cli.exe src\binary\versaorm_cli_windows.exe
```

**En Windows (usando PowerShell):**
```bash
Copy-Item .\versaorm_cli\target\release\versaorm_cli.exe .\src\binary\versaorm_cli_windows.exe
```

### 5. Configurar la Base de Datos de Prueba

Las pruebas automatizadas necesitan conectarse a una base de datos para verificar que las operaciones funcionan correctamente. El proyecto de ejemplo incluye una configuración que puedes adaptar.

-   Crea una base de datos vacía en tu gestor de base de datos local (p. ej., `versaorm_test`).
-   Edita el archivo `example/autoload.php` y ajusta las credenciales de la base de datos en el array `$config` para que coincidan con tu configuración local.

```php
// example/autoload.php
$config = [
    'DB' => [
        'DB_DRIVER' => 'mysql',
        'DB_HOST' => 'localhost',
        'DB_PORT' => 3306,
        'DB_NAME' => 'versaorm_test', // Tu base de datos de prueba
        'DB_USER' => 'local',         // Tu usuario
        'DB_PASS' => 'local',         // Tu contraseña
        'debug' => true
    ]
];
```

### 6. Ejecutar las Pruebas

¡Ya estás listo para verificar tu entorno! Para asegurarte de que todo funciona, ejecuta la suite de pruebas de PHPUnit. Desde la raíz del proyecto:

```bash
vendor/bin/phpunit
```

Si todo está configurado correctamente, deberías ver una salida que indica que todas las pruebas han pasado. Si hay fallos, la salida del error te dará pistas sobre qué pudo haber salido mal (p. ej., un problema de conexión a la base de datos o un binario de Rust que no se encuentra).

---

## Flujo de Trabajo de Desarrollo

Una vez que tu entorno esté listo, tu flujo de trabajo típico será:

1.  **Realizar cambios:** Modifica los archivos `.php` en `src/` o los archivos `.rs` en `versaorm_cli/src/`.
2.  **Recompilar si es necesario:** Si has cambiado cualquier archivo de Rust, **debes** volver a compilar el binario (paso 3) y copiarlo (paso 4).
3.  **Ejecutar pruebas:** Ejecuta `vendor/bin/phpunit` para asegurarte de que tus cambios no han introducido regresiones.
4.  **Escribir nuevas pruebas:** Si añades una nueva funcionalidad, asegúrate de añadir también pruebas que la cubran.
5.  **Commitear y proponer:** Una vez que estés satisfecho con tus cambios, crea un commit y abre un Pull Request en GitHub.

## Siguientes Pasos

Ahora que tienes un entorno de desarrollo funcional, es una buena idea familiarizarte con nuestros **[Estándares de Código](03-coding-standards.md)**.

