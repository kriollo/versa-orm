# Instalación

Hay dos maneras de instalar VersaORM en tu proyecto PHP: a través de Composer (recomendado) o manualmente.

## Requisitos

- PHP 7.4 o superior
- Extensiones de PHP: `json`, `mbstring` (recomendada)
- Acceso a la línea de comandos para Composer
- Uno de los siguientes sistemas de bases de datos:
  - MySQL 5.7+
  - MariaDB 10.2+
  - PostgreSQL 10+
  - SQLite 3.6+

## Instalación con Composer (Recomendado)

Composer es la forma más sencilla de gestionar las dependencias de tu proyecto. Si no tienes Composer instalado, puedes descargarlo desde [getcomposer.org](https://getcomposer.org/).

Para añadir VersaORM a tu proyecto, ejecuta el siguiente comando en la raíz de tu proyecto:

```bash
composer require versaorm/versaorm-php
```

Esto descargará VersaORM y sus dependencias, y configurará el autoloader de PSR-4. Ahora solo necesitas incluir el autoloader de Composer en tu archivo de arranque de PHP (normalmente `index.php` o similar):

```php
require_once 'vendor/autoload.php';
```

¡Y eso es todo! Ya puedes empezar a usar VersaORM.

## Instalación Manual

Si prefieres no usar Composer, puedes instalar VersaORM manualmente.

1.  **Descargar el código fuente:**
    Clona el repositorio de GitHub o descarga el archivo ZIP desde la [página de releases](https://github.com/kriollo/versa-orm/releases).

    ```bash
    git clone https://github.com/kriollo/versa-orm.git
    ```

2.  **Incluir los archivos necesarios:**
    En tu proyecto, necesitas incluir los archivos principales de VersaORM. Puedes hacerlo con `require_once`.

    ```php
    require_once 'path/to/versa-orm/src/VersaORM.php';
    require_once 'path/to/versa-orm/src/VersaModel.php';
    require_once 'path/to/versa-orm/src/QueryBuilder.php';
    require_once 'path/to/versa-orm/src/Traits/VersaORMTrait.php';
    ```

    Asegúrate de reemplazar `path/to/versa-orm/` con la ruta correcta donde hayas clonado o descomprimido el repositorio.

3.  **Verificar el binario de Rust:**
    VersaORM depende de un binario precompilado de Rust para su rendimiento. Estos binarios se encuentran en el directorio `src/binary/`.

    - `versaorm_cli_windows.exe` para Windows
    - `versaorm_cli_linux` para Linux
    - `versaorm_cli_darwin` para macOS

    Asegúrate de que el binario correspondiente a tu sistema operativo tenga permisos de ejecución. En Linux y macOS, puedes hacerlo con:

    ```bash
    chmod +x src/binary/versaorm_cli_linux
    ```

## Siguientes Pasos

Ahora que has instalado VersaORM, el siguiente paso es [configurar la conexión a tu base de datos](configuration.md).
