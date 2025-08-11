# 📦 Instalación de VersaORM

🎉 **¡Instalar VersaORM es súper fácil!** En menos de 5 minutos tendrás el ORM funcionando en tu proyecto (modo PHP / PDO).

## 📋 ¿Qué necesitas antes de empezar?

### ✅ Requisitos Mínimos
- **PHP 7.4 o superior** (si no sabes qué versión tienes, ejecuta `php -v`)
- **Una base de datos** (cualquiera de estas):
  - 🐬 **MySQL 5.7+** (la más común)
  - 🐘 **MariaDB 10.2+** (compatible con MySQL)
  - 🐍 **PostgreSQL 10+** (para aplicaciones avanzadas)
  - 📁 **SQLite 3.6+** (perfecto para desarrollo y aplicaciones simples)

### 🔧 Extensiones PHP (se instalan automáticamente)
- `json`
- `mbstring`

> 💡 **¿No tienes base de datos?** ¡No problem! SQLite se instala automáticamente y no necesita configuración.

---

## 📦 Instalación con Composer (Recomendado - La Más Fácil)

**Composer** es como una "tienda de aplicaciones" para PHP que instala librerías automáticamente.

### 🤔 ¿No tienes Composer? ¡No problem!

1. **Descargar Composer:** Ve a [getcomposer.org](https://getcomposer.org/) y descarga el instalador
2. **Verificar instalación:** Abre terminal/cmd y ejecuta `composer --version`

### 🚀 Instalar VersaORM (1 comando)

En tu proyecto PHP, ejecuta:

```bash
composer require versaorm/versaorm-php
```

¡Eso es todo! Composer descargará automáticamente:
- ✅ VersaORM completo
- ✅ Dependencias
- ✅ Autoload listo

### 📝 Usar VersaORM en tu código

Ahora solo incluye el autoloader en tu archivo principal (ej: `index.php`):

```php
<?php
// Esto carga automáticamente VersaORM y todas sus clases
require_once 'vendor/autoload.php';

// ¡Ya puedes usar VersaORM!
use VersaORM\VersaORM;
use VersaORM\VersaModel;

$orm = new VersaORM([
    'driver' => 'sqlite',
    'database' => 'mi_app.db'
]);

echo "🎉 ¡VersaORM instalado y funcionando!";
```

🎆 **¡Listo! Tienes el ORM más rápido del mundo instalado.**

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

3.  **(Opcional Futuro) Núcleo Nativo**: Por ahora lo omitimos. Cuando se reactive, tu código no necesitará cambios.

## Siguientes Pasos

Ahora que has instalado VersaORM, el siguiente paso es [configurar la conexión a tu base de datos](configuration.md).
